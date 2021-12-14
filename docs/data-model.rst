.. _data-model:

Data model
==========

.. note:: The text below is adapted from §7 of the article `Software Heritage:
  Why and How to Preserve Software Source Code
  <https://hal.archives-ouvertes.fr/hal-01590958/>`_ (in proceedings of `iPRES
  2017 <https://ipres2017.jp/>`_, 14th International Conference on Digital
  Preservation, by Roberto Di Cosmo and Stefano Zacchiroli), which also
  provides a more general description of Software Heritage for the digital
  preservation research community.

In any archival project the choice of the underlying data model—at the logical
level, independently from how data is actually stored on physical media—is
paramount. The data model adopted by Software Heritage to represent the
information that it collects is centered around the notion of *software
artifact*, described below.

It is important to notice that according to our principles, we must store with
every software artifact full information on where it has been found
(provenance), that is also captured in our data model, so we start by providing
some basic information on the nature of this provenance information.


Source code hosting places
--------------------------

Currently, Software Heritage uses of a curated list of source code hosting
places to crawl. The most common entries we expect to place in such a list are
popular collaborative development forges (e.g., GitHub, Bitbucket), package
manager repositories that host source package (e.g., CPAN, npm), and FOSS
distributions (e.g., Fedora, FreeBSD). But we may of course allow also more
niche entries, such as URLs of personal or institutional project collections
not hosted on major forges.

While currently entirely manual, the curation of such a list might easily be
semi-automatic, with entries suggested by fellow archivists and/or concerned
users that want to notify Software Heritage of the need of archiving specific
pieces of endangered source code. This approach is entirely compatible with
Web-wide crawling approaches: crawlers capable of detecting the presence of
source code might enrich the list. In both cases the list will remain curated,
with (semi-automated) review processes that will need to pass before a hosting
place starts to be used.


Software artifacts
------------------

Once the hosting places are known, they will need to be periodically looked at
in order to add to the archive missing software artifacts. Which software
artifacts will be found there?

In general, each software distribution mechanism hosts multiple releases of a
given software at any given time. For VCS (Version Control Systems), this is
the natural behaviour; for software packages, while a single version of a
package is just a snapshot of the corresponding software product, one can often
retrieve both current and past versions of the package from its distribution
site.

By reviewing and generalizing existing VCS and source package formats, we have
identified the following recurrent artifacts as commonly found at source code
hosting places. They form the basic ingredients of the Software Heritage
archive. As the terminology varies quite a bit from technology to technology,
we provide below both the canonical name used in Software Heritage and popular
synonyms.

**contents** (AKA "blobs")
  the raw content of (source code) files as a sequence of bytes, without file
  names or any other metadata.  File contents are often recurrent, e.g., across
  different versions of the same software, different directories of the same
  project, or different projects all together.

**directories**
  a list of named directory entries, each of which pointing to other artifacts,
  usually file contents or sub-directories. Directory entries are also
  associated to some metadata stored as permission bits.

**revisions** (AKA "commits")
  software development within a specific project is essentially a time-indexed
  series of copies of a single "root" directory that contains the entire
  project source code. Software evolves when a developer modifies the content
  of one or more files in that directory and record their changes.

  Each recorded copy of the root directory is known as a "revision". It points
  to a fully-determined directory and is equipped with arbitrary metadata. Some
  of those are added manually by the developer (e.g., commit message), others
  are automatically synthesized (timestamps, preceding commit(s), etc).

**releases** (AKA "tags")
  some revisions are more equals than others and get selected by developers as
  denoting important project milestones known as "releases". Each release
  points to the last commit in project history corresponding to the release and
  carries metadata: release name and version, release message, cryptographic
  signatures, etc.


Additionally, the following crawling-related information are stored as
provenance information in the Software Heritage archive:

**origins**
  code "hosting places" as previously described are usually large platforms
  that host several unrelated software projects. For software provenance
  purposes it is important to be more specific than that.

  Software origins are fine grained references to where source code artifacts
  archived by Software Heritage have been retrieved from. They take the form of
  ``(type, url)`` pairs, where ``url`` is a canonical URL (e.g., the address at
  which one can ``git clone`` a repository or download a source tarball) and
  ``type`` the kind of software origin (e.g., git, svn, or dsc for Debian
  source packages).

..
   **projects**
     as commonly intended are more abstract entities that precise software
     origins. Projects relate together several development resources, including
     websites, issue trackers, mailing lists, as well as software origins as
     intended by Software Heritage.

     The debate around the most apt ontologies to capture project-related
     information for software hasn't settled yet, but the place projects will take
     in the Software Heritage archive is fairly clear. Projects are abstract
     entities, which will be arbitrarily nestable in a versioned
     project/sub-project hierarchy, and that can be associated to arbitrary
     metadata as well as origins where their source code can be found.

**snapshots**
  any kind of software origin offers multiple pointers to the "current" state
  of a development project. In the case of VCS this is reflected by branches
  (e.g., master, development, but also so called feature branches dedicated to
  extending the software in a specific direction); in the case of package
  distributions by notions such as suites that correspond to different maturity
  levels of individual packages (e.g., stable, development, etc.).

  A "snapshot" of a given software origin records all entry points found there
  and where each of them was pointing at the time. For example, a snapshot
  object might track the commit where the master branch was pointing to at any
  given time, as well as the most recent release of a given package in the
  stable suite of a FOSS distribution.

**visits**
  links together software origins with snapshots. Every time an origin is
  consulted a new visit object is created, recording when (according to
  Software Heritage clock) the visit happened and the full snapshot of the
  state of the software origin at the time.

.. note::
  This model currently records visits as a single point in time. However, the
  actual visit process is not instantaneous. Loaders can record successive
  changes to the state of the visit, as their work progresses, as updates to
  the visit object.

Data structure
--------------

.. _swh-merkle-dag:
.. figure:: images/swh-merkle-dag.svg
   :width: 1024px
   :align: center

   Software Heritage archive as a Merkle DAG, augmented with crawling
   information (click to zoom).


With all the bits of what we want to archive in place, the next question is how
to organize them, i.e., which logical data structure to adopt for their
storage. A key observation for this decision is that source code artifacts are
massively duplicated. This is so for several reasons:

* code hosting diaspora (i.e., project development moving to the most
  recent/cool collaborative development technology over time);
* copy/paste (AKA "vendoring") of parts or entire external FOSS software
  components into other software products;
* large overlap between revisions of the same project: usually only a very
  small amount of files/directories are modified by a single commit;
* emergence of DVCS (distributed version control systems), which natively work
  by replicating entire repository copies around. GitHub-style pull requests
  are the pinnacle of this, as they result in creating an additional repository
  copy at each change done by a new developer;
* migration from one VCS to another—e.g., migrations from Subversion to Git,
  which are really popular these days—resulting in additional copies, but in a
  different distribution format, of the very same development histories.

These trends seem to be neither stopping nor slowing down, and it is reasonable
to expect that they will be even more prominent in the future, due to the
decreasing costs of storage and bandwidth.

For this reason we argue that any sustainable storage layout for archiving
source code in the very long term should support deduplication, allowing to pay
for the cost of storing source code artifacts that are encountered more than
once only once. For storage efficiency, deduplication should be supported for
all the software artifacts we have discussed, namely: file contents,
directories, revisions, releases, snapshots.

Realizing that principle, the Software Heritage archive is conceptually a
single (big) `Merkle Direct Acyclic Graph (DAG)
<https://en.wikipedia.org/wiki/Merkle_tree>`_, as depicted in Figure
:ref:`Software Heritage Merkle DAG <swh-merkle-dag>`. In such a graph each of
the artifacts we have described—from file contents up to entire
snapshots—correspond to a node.  Edges between nodes emerge naturally:
directory entries point to other directories or file contents; revisions point
to directories and previous revisions, releases point to revisions, snapshots
point to revisions and releases. Additionally, each node contains all metadata
that are specific to the node itself rather than to pointed nodes; e.g., commit
messages, timestamps, or file names. Note that the structure is really a DAG,
and not a tree, due to the fact that the line of revisions nodes might be
forked and merged back.

..
   directory: fff3cc22cb40f71d26f736c082326e77de0b7692
   parent: e4feb05112588741b4764739d6da756c357e1f37
   author: Stefano Zacchiroli <zack@upsilon.cc>
   date: 1443617461 +0200
   committer: Stefano Zacchiroli <zack@upsilon.cc>
   commiter_date: 1443617461 +0200
   message:
     objstorage: fix tempfile race when adding objects

     Before this change, two workers adding the same
     object will end up racing to write <SHA1>.tmp.
     [...]

     revisionid: 64a783216c1ec69dcb267449c0bbf5e54f7c4d6d
     A revision node in the Software Heritage DAG

In a Merkle structure each node is identified by an intrinsic identifier
computed as a cryptographic hash of the node content. In the case of Software
Heritage identifiers are computed taking into account both node-specific
metadata and the identifiers of child nodes.

Consider the revision node in the picture whose identifier starts with
`c7640e08d..`. it points to a directory (identifier starting with
`45f0c078..`), which has also been archived. That directory contains a full
copy, at a specific point in time, of a software component—in the example the
`Hello World <https://forge.softwareheritage.org/source/helloworld/>`_ software
component available on our forge. The revision node also points to the
preceding revision node (`43ef7dcd..`) in the project development history.
Finally, the node contains revision-specific metadata, such as the author and
committer of the given change, its timestamps, and the message entered by the
author at commit time.

The identifier of the revision node itself (`c7640e08d..`) is computed as a
cryptographic hash of a (canonical representation of) all the information shown
in figure. A change in any of them—metadata and/or pointed nodes—would result
in an entirely different node identifier. All other types of nodes in the
Software Heritage archive behave similarly.

The Software Heritage archive inherits useful properties from the underlying
Merkle structure. In particular, deduplication is built-in. Any software
artifacts encountered in the wild gets added to the archive only if a
corresponding node with a matching intrinsic identifier is not already
available in the graph—file content, commits, entire directories or project
snapshots are all deduplicated incurring storage costs only once.

Furthermore, as a side effect of this data model choice, the entire development
history of all the source code archived in Software Heritage—which ambitions to
match all published source code in the world—is available as a unified whole,
making emergent structures such as code reuse across different projects or
software origins, readily available. Further reinforcing the Software Heritage
use cases, this object could become a veritable "map of the stars" of our
entire software commons.


Extended data model
-------------------

In addition to the artifacts detailed above used to represent original software
artifacts, the Software Heritage archive stores information about these
artifacts.

**extid**
  a relationship between an original identifier of an artifact, in its
  native/upstream environment, and a `core SWHID <persistent-identifiers>`,
  which is specific to Software Heritage. As such, it is a triple made of:

  * the external identifier, stored as bytes whose format is opaque to the
    data model
  * a type (a simple name and a version), to identify the type of relationship
  * the "target", which is a core SWHID

**raw extrinsic metadata**
  an opaque bytestring, along with its format (a simple name), an identifier
  of the object the metadata is about and in which context (similar to a
  `qualified SWHID <persistent-identifiers>`), and provenance information
  (the authority who provided it, the fetcher tool used to get it, and the
  data it was discovered at).

  It provides both a way to store information about an artifact contributed by
  external entities, after the artifact was created, and an escape hatch to
  store metadata that would not otherwise fit in the data model.
