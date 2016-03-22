Git sha1 computation
--------------------

Document to describe how the git sha1 computation takes place.

### commit/revision

sha1 git commit/revision computation:

    commit `size`\0
    tree `sha1-git-tree-and-subtree-in-plain-hex-string`
    ([parent `commit-parent-n`])
    author `name` <`email`> `date-ts` `date-offset`
    committer `name` <`email`> `date-ts` `date-offset`
    ([extra-header-key-n extra-header-value-n])

    `commit-message`
    (inline-gpg-signature)


Notes:
- [] denotes list of entries (one per line)
- () denotes optional entry. For example, the parent entry is optional.
- empty line at the end of the commit message
- timestamp example: 1444054085
- date offset for example: +0200, -0100

sources:
- commit_tree_extended: https://github.com/git/git/blob/8d530c4d64ffcc853889f7b385f554d53db375ed/commit.c#L1522
- commit_tree: https://github.com/git/git/blob/8d530c4d64ffcc853889f7b385f554d53db375ed/commit.c#L1392

Example:

```sh
$ cat commit.txt
tree 85a74718d377195e1efd0843ba4f3260bad4fe07
parent 01e2d0627a9a6edb24c37db45db5ecb31e9de808
author Linus Torvalds <torvalds@linux-foundation.org> 1436739030 -0700
committer Linus Torvalds <torvalds@linux-foundation.org> 1436739030 -0700
svn-repo-uuid 046f1af7-66c2-d61b-5410-ce57b7db7bff
svn-revision 10

Linux 4.2-rc2
```

```
$ cat commit.txt | git hash-object -t commit --stdin
010d34f384fa99d047cdd5e2f41e56e5c2feee45
```

### directory/tree

sha1 git directory/tree computation:

    tree `tree-size`\0
    <file-perm> <file-name>\0<file-sha1-in-20-bytes-string>...<dir-perm> <dir-name>\0<dir-sha1-in-20-bytes-string>...


Notes:
- no newline separator between tree entries
- no empty newline at the end of the tree entries
- tree content header size is the length of the content
- The tree entries are ordered according to bytes in their <name> properties.

Note: Tree entries referencing trees are sorted as if their name have a trailing /
at their end.

Possible permissions are:
- 100644 - file
- 40000  - directory
- 100755 - executable file
- 120000 - symbolink link
- 160000 - git link (relative to submodule)

### content/file

sha1 git content computation:

    blob `blob-size`\0
    `blob-content`

Notes:
- no newline at the end of the blob content

Compress with DEFLATE and compute sha1
