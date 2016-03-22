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

Examples:

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

commit: 44cc742a8ca17b9c279be4cc195a93a6ef7a320e
```
$ git cat-file -p 44cc742a8ca17b9c279be4cc195a93a6ef7a320e
...
tree b134f9b7dc434f593c0bab696345548b37de0558
parent 689664ae944b4692724f13b709a4e4de28b54e57
parent c888305e1efbaa252d01b4e5e6b778f865a97514
author Jiang Xin <worldhello.net@gmail.com> 1428538899 +0800
committer Jiang Xin <worldhello.net@gmail.com> 1428538899 +0800
gpgsig -----BEGIN PGP SIGNATURE-----
 Version: GnuPG v1.4.13 (Darwin)

 iQIcBAABAgAGBQJVJcYsAAoJEBiY3kIkQRNJVAUQAJ8/XQIfMqqC5oYeEFfHOPYZ
 L7qy46bXHVBa9Qd8zAJ2Dou3IbI2ZoF6/Et89K/UggOycMlt5FKV/9toWyuZv4Po
 L682wonoxX99qvVTHo6+wtnmYO7+G0f82h+qHMErxjP+I6gzRNBvRr+SfY7VlGdK
 wikMKOMWC5smrScSHITnOq1Ews5pe3N7qDYMzK0XVZmgDoaem4RSWMJs4My/qVLN
 e0CqYWq2A22GX7sXl6pjneJYQvcAXUX+CAzp24QnPSb+Q22Guj91TcxLFcHCTDdn
 qgqMsEyMiisoglwrCbO+D+1xq9mjN9tNFWP66SQ48mrrHYTBV5sz9eJyDfroJaLP
 CWgbDTgq6GzRMehHT3hXfYS5NNatjnhkNISXR7pnVP/obIi/vpWh5ll6Gd8q26z+
 a/O41UzOaLTeNI365MWT4/cnXohVLRG7iVJbAbCxoQmEgsYMRc/pBAzWJtLfcB2G
 jdTswYL6+MUdL8sB9pZ82D+BP/YAdHe69CyTu1lk9RT2pYtI/kkfjHubXBCYEJSG
 +VGllBbYG6idQJpyrOYNRJyrDi9yvDJ2W+S0iQrlZrxzGBVGTB/y65S8C+2WTBcE
 lf1Qb5GDsQrZWgD+jtWTywOYHtCBwyCKSAXxSARMbNPeak9WPlcW/Jmu+fUcMe2x
 dg1KdHOa34shrKDaOVzW
 =od6m
 -----END PGP SIGNATURE-----

Merge branch 'master' of git://github.com/alexhenrie/git-po

* 'master' of git://github.com/alexhenrie/git-po:
  l10n: ca.po: update translation
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
