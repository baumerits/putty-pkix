Summary
=======
This readme contains information about how to build PuTTY-pkix from source. The PuTTY version used in the documentation is 0.70. Please substitute with your PuTTY version if using another version of the patch file.

Requirements
============

putty_pkix_070_git.patch is found in the root of this repository.

The PuTTY 0.70 source checked out from git at: ` git clone --branch 0.70 git://git.tartarus.org/simon/putty.git `

Microsoft Visual C compiler (tested with visual studio 2017 Community Edition)

(Cygwin, BCC5.5 or LCC may also work)

Details
=======

#### 1: Apply the patch

Apply the putty_pkix_070_git.patch to the source code.

` patch -p1 -i putty_pkix_070_git.patch `

Ignore any patch warnings about offsets.

#### 2: Generate the Makefiles

` perl ./mkfiles.pl `

#### 3: Build the solution file './windows/VS2012/putty.sln' (Visual Studio only)

#### 4: Use

If the build was successful it should now be possible to use the newly compiled versions of PuTTY and Pageant. The executables will be found in the windows sub-directory of the PuTTY source.

#### Notes about the build environment

It is possible to build the wincrypt patched version of PuTTY with Microsoft Visual C. Cygwin / BCC / LCC may also work but aren't tested for each patch. The recommended build environment is Visual C.
