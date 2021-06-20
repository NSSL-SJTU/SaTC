import re


def main(file):

    data_dependency_set = set()

    with open(file, "r") as f:
        content = f.read().splitlines()

    for line in content:
        res = re.search(r'"(\w+)"', line)
        if res:
            data_dependency_set.add(res.group(1))
            print(res.group(1))

    print("res: ", len(data_dependency_set))

if __name__ == "__main__":
    file = "/home/lin/code/Get_form/Update_JSParse_Version/DIR-878/ref2share.log"

    main(file)