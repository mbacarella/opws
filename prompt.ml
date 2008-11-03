(*
#load "unix.cma"
open Unix
*)

let read_password () =
  Printf.printf "Safe combination: ";
  read_line()
(*
  let term_init = tcgetattr stdin in
  let term_no_echo = {term_init with c_echo = false; } in
    tcsetattr stdin TCSANOW term_no_echo;
  let password = read_line () in
      tcsetattr stdin TCSAFLUSH term_init;
      password
*)

