"""Independent iterative carry/forest oracle, no production imports."""
import hashlib


def tree(entries):
    forest = []
    for index, value in enumerate(entries):
        node = (index, index+1, hashlib.sha256(b"\0"+value).digest(), None, None)
        carry = index
        while carry & 1:
            left = forest.pop()
            node = combine(left, node)
            carry >>= 1
        forest.append(node)
    if not forest:
        return (0, 0, hashlib.sha256(b"").digest(), None, None)
    node = forest.pop()
    while forest:
        node = combine(forest.pop(), node)
    return node


def combine(left, right):
    return (left[0], right[1], hashlib.sha256(b"\1"+left[2]+right[2]).digest(), left, right)


def path(node, index):
    siblings = []
    while node[3] is not None:
        left, right = node[3], node[4]
        if index < left[1]:
            siblings.append(right[2])
            node = left
        else:
            siblings.append(left[2])
            node = right
    return tuple(reversed(siblings))
