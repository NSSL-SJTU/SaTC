#!/bin/bash

function green
{
	echo "$(tput setaf 6 2>/dev/null)$@$(tput sgr0 2>/dev/null)"
}

function red
{
	echo "$(tput setaf 1 2>/dev/null)$@$(tput sgr0 2>/dev/null)"
}

RED=$(tput setaf 1 2>/dev/null)
GREEN=$(tput setaf 2 2>/dev/null)
NORMAL=$(tput sgr0 2>/dev/null)
center_align() {
	MSG="$1"
	PADDING="$2"
	COLOR="$3"

	[ -z "$PADDING" ] && PADDING="="
	[ -z "$COLOR" ] && COLOR="$GREEN"
	[ -e $(which tput) ] && COL=$(tput cols) || COL=80
	let PAD=\($COL-${#MSG}-2\)/2

	printf "$COLOR"
	printf -- "$PADDING%.0s" $(eval "echo {1..$PAD}")
	printf " %s " "$MSG"
	printf -- "$PADDING%.0s" $(eval "echo {1..$PAD}")
	[ $[$PAD*2 + ${#MSG} + 2] -lt $COL ] && printf "$PADDING"
	printf "$NORMAL"
	printf "\n"
}

function careful_pull
{
	git pull 2>&1 | tee /dev/stderr | grep -q "ssh_exchange_identification:"
	CMD_STATUS=${PIPESTATUS[0]} GREP_MATCH=${PIPESTATUS[2]}

	if [ "$GREP_MATCH" -eq 0 ]
	then
		red "Too many concurrent connections to the server. Retrying after sleep."
		sleep $[$RANDOM % 5]
		careful_pull
		return $?
	else
		return $CMD_STATUS
	fi
}

function checkup
{
	# http://stackoverflow.com/questions/1593051/how-to-programmatically-determine-the-current-checked-out-git-branch
	branch_name="$(git symbolic-ref HEAD 2>/dev/null)" ||
	branch_name="(unnamed branch)"     # detached HEAD
	branch_name=${branch_name##refs/heads/}

	git status --porcelain | egrep '^(M| M)' >/dev/null 2>/dev/null
	is_dirty=$?

    git status | egrep --color=never 'have diverged|each, respectively|is behind|is ahead of' >/dev/null 2>/dev/null
    is_desync=$?

	[ "$branch_name" != "master" ]
	isnt_master=$?

	if [ $is_dirty == 0 -o $isnt_master == 0 -o $is_desync == 0 ]; then
		center_align $1 "-"
	fi

	if [ $isnt_master == 0 ]; then
		echo "On branch $RED$branch_name$NORMAL"
	fi

    git status | egrep --color=never 'have diverged|each, respectively|is behind|is ahead of'

	if [ $is_dirty == 0 ]; then
		echo "Uncommitted files:"
		git status --porcelain | egrep --color=always '^(M| M)'
	fi
}

function do_one
{
	DIR=$1
	shift

	[ "$1" == "CHECKUP" -o "$PREPEND" == "1" ] && PRINT_HEADERS=0 || PRINT_HEADERS=1

	[ $PRINT_HEADERS -eq 1 ] && center_align "RUNNING ON: $DIR" "#"

	cd $DIR
	if [ "$1" == "CAREFUL_PULL" ]; then
		careful_pull
		RETURN_CODE=$?
	elif [ "$1" == "CHECKUP" ]; then
		checkup $DIR
        RETURN_CODE=0
	elif [ "$PREPEND" == "1" ]; then
		git "$@" 2>&1| sed -e "s/^/$DIR: /"
		RETURN_CODE=${PIPESTATUS[0]}
	else
		git "$@"
		RETURN_CODE=$?
	fi
	cd ..

	if [ $PRINT_HEADERS -eq 1 ]
	then
		[ $RETURN_CODE -eq 0 ] && center_align "SUCCESS" "-" || center_align "FAILURE (return code $RETURN_CODE)" "-" "$RED"
	fi

	[ -n "$EXIT_FAILURE" -a $RETURN_CODE -ne 0 ] && exit 1
	[ $RETURN_CODE -eq 0 ] && SUCCESSFUL="$SUCCESSFUL $DIR" || FAILED="$FAILED $DIR"
}

function do_concurrent
{
	# special thanks to:
	# - http://stackoverflow.com/questions/1570262/shell-get-exit-code-of-background-process
	# - http://www.linuxjournal.com/content/bash-associative-arrays

	declare -A procs
	for i in $REPOS
	do
		EXIT_FAILURE=1 do_one $i "$@" &
		procs[$i]=$!
	done

	for i in $REPOS
	do
		#results[$i]=$?
		#echo "RESULT: $i ${results[$i]}"

		if wait ${procs[$i]}
		then
			SUCCESSFUL="$SUCCESSFUL $i"
		else
			FAILED="$FAILED $i"
		fi
	done

	report
}

function do_all
{
	for i in $REPOS
	do
		do_one $i "$@"
	done
	report
}

function report
{
	if [ -n "$SUCCESSFUL" ]
	then
		echo ""
		green "# Succeeded:"
		echo $SUCCESSFUL
	fi
	if [ -n "$FAILED" ]
	then
		echo ""
		red "# Failed:"
		echo $FAILED
	fi
}

function do_screen
{
	SESSION=git-all-$$
	screen -S $SESSION -d -m sleep 2
	for i in $REPOS
	do
		screen -S $SESSION -X screen -t $i bash -c "REPOS=$i EXIT_FAILURE=1 CONCURRENT=no ./git_all.sh $@ || bash"
	done
	screen -rd $SESSION

}

[ -z "$REPOS" ] && REPOS=$(ls -d */.git | sed -e "s/\/\.git//")

if [ "$CONCURRENT" == "screen" ]
then
	do_screen "$@"
elif [ "$CONCURRENT" == "yes" ]
then
	do_concurrent "$@"
else
	do_all "$@"
fi
