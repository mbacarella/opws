(* Interface for prompting from the command-line
   Copyright (C) 2008 Michael Bacarella <mbac@panix.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*)


open Unix

let print_flush s =
  Pervasives.print_string s;
  Pervasives.flush Pervasives.stdout

let read_password prompt =
  print_flush prompt;
  let term_init = tcgetattr stdin in
  let term_no_echo = {term_init with c_echo = false; } in
    tcsetattr stdin TCSANOW term_no_echo;
  let password =
    try
      Some (read_line ())
    with
      | _ -> None (* term echo back on no matter what! *)
  in
    tcsetattr stdin TCSAFLUSH term_init;
    print_flush "\n";
    password

let test () =
  match read_password "enter combination: " with
    | None -> failwith "error reading combination";
    | Some (password) -> Printf.printf "I enjoyed reading your password -->%s<--\n" password

(*
let () =
  test ()
*)
