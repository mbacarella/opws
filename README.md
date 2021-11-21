opws
====

An implementation of Password Safe in OCaml.

Status
--

It will *probably* be able to successfully decrypt your .psafe3 database and
print to a text file.


This was my first OCaml project, started 12 years ago (2009) with not much
attention. Freshened up recently to build with dune. There's lots of room
for improvement.

Remarks
---

There are a few deficiencies here.

1. The cryptographic functions may not be able to resist side-channel information
leak attacks. Worry about this if you copy/paste the code to be used in some
kind of service.

2. The code used to mutate strings but that became unfashionable in favor of using
bytes in later OCaml releases. To make that build I did a naive swap-replace of
those functions. A more enlightened approach is possible.

3. A lot of the bit manipulation code exists in the standard library now, so this
could use a good refactor.

4. Not all fields are supported. I simply didn't try generating a database with
every possible field filled in. It should be pretty easy to add them to the
variant though.

5. If you're a student of OCaml, the interaction between the CBC and Twofish
modules are begging to be functorized. You may wish to try that.
