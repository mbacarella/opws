
type clear_header = {
  tag : string;  (* TAG: 4-ascii chars *)
  salt : string; (* SALT 256-bit: randomly generated *)
  (* P' is a "stretched key" generated from user passphrase + salt as specified
     in the KEYSTRETCH algorithm; H() = SHA-256 in hash-based keystretch *)
  iter : int;    (* 32-bit ITER: number of iterations to use in computing P' *)
  hofp : string; (* 256-bit H(P'); where H() = SHA-256 *)
  b1 : string;   (* 128-bit B1: *)
  b2 : string;   (* 128-bit B2: *)
  b3 : string;   (* 128-bit B3: *)
  b4 : string;   (* 128-bit B4: *)
  iv : string;   (* 128-bit IV: 128-bit random Initial Value for CBC mode *)
}


(* KEYSTRETCH/hash implementation as specified here http://www.cs.berkeley.edu/~daw/papers/keystretch.ps *)
let keystretch kshort salt iters =
  let digest = Sha256.digest in
  let rec ks_inner i sha =
    if i = iters then
      sha
    else
      ks_inner (i+1) (digest sha)
  in
  let m = Buffer.create 32 in
    Buffer.add_buffer m kshort;
    Buffer.add_buffer m salt;
    ks_inner 0 (digest m)

let read_blob chan n =
  let rec read_chars b = function
    | 0 -> b
    | i -> (Buffer.add_char b (input_char chan); read_chars b (i-1))
  in
    Buffer.contents (read_chars (Buffer.create n) n)
    
let load_clrtxt_header chan =
  let in_bits off bits =
    match (off mod 8,bits mod 8) with
      | (0,0) ->
          begin
            seek_in chan (off / 8);
            let b = read_blob chan (bits / 8) in
              b
          end
      | (_,_) -> raise (Invalid_argument "in_bits: off and bits must be multiples of 8")
  in                 
  let clrtxt_header = 
    {
      tag = in_bits 0 32;
      salt = in_bits 32 256;
      iter = Bin.unpack32_le (in_bits 288 32);
      hofp = in_bits 320 256;
      b1 = in_bits 576 128;
      b2 = in_bits 704 128;
      b3 = in_bits 832 128;
      b4 = in_bits 960 128;
      iv = in_bits 1088 128;
    }
  in
    clrtxt_header

let buffer_of_string s =
  let b = Buffer.create (String.length s) in
    begin
      Buffer.add_string b s;
      b
    end
      
let load_records ch chan p' =
  let join ctx a b = String.concat "" [Twofish.decrypt ctx a; Twofish.decrypt ctx b] in
  let joinkeys = join (Twofish.init p') in
  let k = joinkeys ch.b1 ch.b2 in
  let l = joinkeys ch.b3 ch.b4 in
  let iv = ch.iv in
    Printf.printf "random key K: %s\nrandom key L: %s\nCBC IV: %s\n" (Bin.hexstring k) (Bin.hexstring l) (Bin.hexstring iv)

let load_database fn passphrase =
  let chan = open_in_gen [Open_binary] 0 fn in
  try
    begin
      let ch = load_clrtxt_header chan in
      let p' = keystretch (buffer_of_string passphrase) (buffer_of_string ch.salt) ch.iter in       
        let hofp' = Sha256.digest p' in (* hash yet another time... *)
          if (buffer_of_string ch.hofp) = hofp' then
            load_records ch chan (Buffer.contents p')
          else
            (Printf.printf "Passphrase incorrect.\n"; exit 1)
          close_in chan
    end
  with
    | Sys_error fn -> failwith ("load_database: error accessing " ^ fn)
    | End_of_file -> failwith ("load_database: "^fn^": corrupted database (EOF reached unexpectedly)")

let () =
  let fn = "/home/mbacarella/.pwsafe.psafe3" in
    Printf.printf "Opening database at %s\n" fn;
    load_database fn (Prompt.read_password ());
  ()
