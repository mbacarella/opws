(lang dune 2.7)

(name opws)

(generate_opam_files true)

(license "GPL")

(authors "Michael Bacarella <m@bacarella.com>")

(maintainers "Michael Bacarella <m@bacarella.com>")

(homepage "https://github.com/mbacarella/opws")

(source
 (github mbacarella/opws))

(package
 (name opws)
 (synopsis "OCaml command-line Password Safe")
 (description "Work in progress / proof of concept. Read-only.")
 (depends
  conf-ncurses
  dune-configurator
  (ocaml
   (>= 4.02.0))))
