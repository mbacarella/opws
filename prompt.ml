
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
