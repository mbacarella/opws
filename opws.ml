(* An implementation of PWSAFE command-line which supports v3 databases
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

   See formatv3.txt for some answers
*)

open Printf

let echo_passwords = ref false
let iff p t e = if p then t else e

type clear_header =
  { tag : string;
    salt : string;
    iter : int;
    hofp : string;
    b1 : string;
    b2 : string;
    b3 : string;
    b4 : string;
    iv : string
  }

type database_cursor =
  { ctx : Twofish.ctx;
    chan : in_channel;
    chan_start : int;
    mutable chan_pos : int;
    mutable block : string option;
    mutable block_pos : int option;
    cbc : Cbc.state
  }

exception End_of_database

let cursor_nextblock cur =
  let blocksize = 16 in
  (* find start of next block *)
  assert (cur.chan_pos mod blocksize = 0);
  (* read the block *)
  seek_in cur.chan (cur.chan_start + cur.chan_pos);
  let block = String.create blocksize in
  let dec = Twofish.decrypt cur.ctx in
  really_input cur.chan block 0 blocksize;
  if block = "PWS3-EOFPWS3-EOF"
  then raise End_of_database
  else (
    cur.block <- Some (Cbc.decrypt cur.cbc dec block);
    cur.block_pos <- Some 0;
    (* get in position for the next call *)
    cur.chan_pos <- cur.chan_pos + blocksize)

let rec cursor_getchar cur =
  match cur.block, cur.block_pos with
  | None, None | Some _, Some 16 ->
    cursor_nextblock cur;
    cursor_getchar cur
  | Some blk, Some pos ->
    cur.block_pos <- Some (pos + 1);
    blk.[pos]
  | _, _ -> failwith "read_byte: unexpected blk, pos"

let cursor_getshort cur =
  let a = cursor_getchar cur in
  let b = cursor_getchar cur in
  Bin.unpack16_le (sprintf "%c%c" a b)

let cursor_gettime cur =
  let a = cursor_getchar cur in
  let b = cursor_getchar cur in
  let c = cursor_getchar cur in
  let d = cursor_getchar cur in
  Bin.unpack32_le (sprintf "%c%c%c%c" a b c d)

let cursor_gets cur = function
  | 0 -> ""
  | length ->
    let b = Buffer.create length in
    let rec loop = function
      | 0 -> Buffer.contents b
      | i ->
        Buffer.add_char b (cursor_getchar cur);
        loop (i - 1)
    in
    loop length

type header =
  | Version of int
  | Header_UUID of string
  | Non_default_preferences of string
  | Tree_display_status of string
  | Timestamp_of_last_save of int
  | Who_performed_last_save of string
  | What_performed_last_save of string
  | Last_saved_by_user of string
  | Last_saved_on_host of string
  | Database_name of string
  | Database_description of string
  | Database_filters of string
  | End_of_header

type record =
  | Record_UUID of string
  | Group of string
  | Title of string
  | Username of string
  | Notes of string
  | Password of string
  | Creation_time of int
  | Password_modification_time of int
  | Last_access_time of int
  | Password_expiry_time of int
  | Reserved of string
  | Last_modification_time of int
  | URL of string
  | Autotype of string
  | Password_history of string
  | Password_policy of string
  | Password_expiry_interval of int
  | End_of_record

let header_of_code cur length = function
  | 0x00 ->
    assert (length = 2);
    Version (cursor_getshort cur)
  | 0x01 ->
    assert (length = 16);
    Header_UUID (cursor_gets cur 16)
  | 0x02 -> Non_default_preferences (cursor_gets cur length)
  | 0x03 -> Tree_display_status (cursor_gets cur length)
  | 0x04 ->
    assert (length = 8);
    Timestamp_of_last_save (cursor_gettime cur)
  | 0x05 -> Who_performed_last_save (cursor_gets cur length)
  | 0x06 -> What_performed_last_save (cursor_gets cur length)
  | 0x07 -> Last_saved_by_user (cursor_gets cur length)
  | 0x08 -> Last_saved_on_host (cursor_gets cur length)
  | 0x09 -> Database_name (cursor_gets cur length)
  | 0x0a -> Database_description (cursor_gets cur length)
  | 0x0b -> Database_filters (cursor_gets cur length)
  | 0xff -> End_of_header
  | code -> failwith ("header_of_code: unknown code: " ^ string_of_int code)

let entry_of_code cur length = function
  | 0x01 ->
    assert (length = 16);
    Record_UUID (cursor_gets cur 16)
  | 0x02 -> Group (cursor_gets cur length)
  | 0x03 -> Title (cursor_gets cur length)
  | 0x04 -> Username (cursor_gets cur length)
  | 0x05 -> Notes (cursor_gets cur length)
  | 0x06 -> Password (cursor_gets cur length)
  | 0x07 ->
    assert (length = 4);
    Creation_time (cursor_gettime cur)
  | 0x08 ->
    assert (length = 4);
    Password_modification_time (cursor_gettime cur)
  | 0x09 ->
    assert (length = 4);
    Last_access_time (cursor_gettime cur)
  | 0x0a ->
    assert (length = 4);
    Password_expiry_time (cursor_gettime cur)
  | 0x0b ->
    assert (length = 4);
    Reserved (cursor_gets cur 4)
  | 0x0c ->
    assert (length = 4);
    Last_modification_time (cursor_gettime cur)
  | 0x0d -> URL (cursor_gets cur length)
  | 0x0e -> Autotype (cursor_gets cur length)
  | 0x0f -> Password_history (cursor_gets cur length)
  | 0x10 -> Password_policy (cursor_gets cur length)
  | 0x11 ->
    assert (length = 2);
    Password_expiry_interval (cursor_getshort cur)
  | 0xFF -> End_of_record
  | code -> failwith ("entry_of_code: unknown code: " ^ string_of_int code)

(*
 KEYSTRETCH/hash implementation as specified here:
   http://www.cs.berkeley.edu/~daw/papers/keystretch.ps
*)

let keystretch kshort salt iters =
  let digest = Sha256.digest in
  let rec ks_inner i sha = if i = iters then sha else ks_inner (i + 1) (digest sha) in
  let m = Buffer.create 32 in
  Buffer.add_buffer m kshort;
  Buffer.add_buffer m salt;
  ks_inner 0 (digest m)

let read_blob chan n =
  let rec read_chars b = function
    | 0 -> b
    | i ->
      Buffer.add_char b (input_char chan);
      read_chars b (i - 1)
  in
  Buffer.contents (read_chars (Buffer.create n) n)

let load_clrtxt_header chan =
  let in_bits off bits =
    match off mod 8, bits mod 8 with
    | 0, 0 ->
      seek_in chan (off / 8);
      let b = read_blob chan (bits / 8) in
      b
    | _, _ -> raise (Invalid_argument "in_bits: off and bits must be multiples of 8")
  in
  let clrtxt_header =
    { tag = in_bits 0 32;
      salt = in_bits 32 256;
      iter = Bin.unpack32_le (in_bits 288 32);
      hofp = in_bits 320 256;
      b1 = in_bits 576 128;
      b2 = in_bits 704 128;
      b3 = in_bits 832 128;
      b4 = in_bits 960 128;
      iv = in_bits 1088 128
    }
  in
  clrtxt_header

let buffer_of_string s =
  let b = Buffer.create (String.length s) in
  Buffer.add_string b s;
  b

let decrypt_database k l ch chan =
  let cbc = Cbc.init ch.iv in
  let cur =
    { ctx = Twofish.init k;
      chan;
      chan_start = 152;
      chan_pos = 0;
      block = None;
      block_pos = None;
      cbc
    }
  in
  let read_field f cur =
    cursor_nextblock cur;
    let a = cursor_getchar cur in
    let b = cursor_getchar cur in
    let c = cursor_getchar cur in
    let d = cursor_getchar cur in
    let x = Bin.unpack32_le (sprintf "%c%c%c%c" a b c d) in
    let code = int_of_char (cursor_getchar cur) in
    f cur x code
  in
  let next_header_field = read_field header_of_code in
  let next_entry_field = read_field entry_of_code in
  let rec collect_headers cur accum = function
    | End_of_header -> List.rev accum
    | header -> collect_headers cur (header :: accum) (next_header_field cur)
  in
  let rec collect_entries cur accum = function
    | End_of_record -> List.rev accum
    | record -> collect_entries cur (record :: accum) (next_entry_field cur)
  in
  let rec collect_records cur accum =
    let entries = collect_entries cur [] (next_entry_field cur) in
    try (* XXX: not tail recursive *)
        collect_records cur (entries :: accum) with
    | End_of_database -> List.rev (entries :: accum)
  in
  let headers = collect_headers cur [] (next_header_field cur) in
  let records = collect_records cur [] in
  headers, records

let make_keys ch p' =
  let join ctx a b =
    let a' = Twofish.decrypt ctx a in
    let b' = Twofish.decrypt ctx b in
    String.concat "" [ a'; b' ]
  in
  let joinkeys = join (Twofish.init p') in
  let k = joinkeys ch.b1 ch.b2 in
  let l = joinkeys ch.b3 ch.b4 in
  let iv = ch.iv in
  k, l, iv

let load_database fn passphrase =
  let chan = open_in_gen [ Open_binary ] 0 fn in
  try
    let ch = load_clrtxt_header chan in
    let b_passphrase = buffer_of_string passphrase in
    let b_salt = buffer_of_string ch.salt in
    let p' = keystretch b_passphrase b_salt ch.iter in
    let hofp' = Sha256.digest p' in
    if buffer_of_string ch.hofp = hofp'
    then (
      let k, l, iv = make_keys ch (Buffer.contents p') in
      let hdrs, recs = decrypt_database k l ch chan in
      close_in chan;
      hdrs, recs)
    else (
      printf "Passphrase incorrect.\n";
      close_in chan;
      exit 1)
  with
  | Sys_error fn -> failwith ("load_database: error accessing " ^ fn)
  | End_of_file ->
    failwith ("load_database: " ^ fn ^ ": corrupted database (unexpected end of file)")

let format_field = function
  | Group group -> "Group: " ^ group ^ "\n"
  | Title title -> "Title: " ^ title ^ "\n"
  | Username username -> "Username: " ^ username ^ "\n"
  | Password password ->
    "Password: " ^ (if !echo_passwords then password else "************") ^ "\n"
  | Notes notes -> "Notes: " ^ notes ^ "\n"
  | URL url -> "URL: " ^ url ^ "\n"
  | Autotype autotype -> "Autotype: " ^ autotype ^ "\n"
  | Password_expiry_interval _
  | Password_policy _
  | Password_history _
  | Last_modification_time _
  | Reserved _
  | Password_expiry_time _
  | Last_access_time _
  | Password_modification_time _
  | Creation_time _
  | Record_UUID _
  | End_of_record -> ""

let rec dump_fields = function
  | [] -> "\n"
  | f :: fields -> format_field f ^ dump_fields fields

let rec dump_records match_fun = function
  | [] -> ()
  | r :: records ->
    if match_fun r then printf "-----\n%s" (dump_fields r) else ();
    dump_records match_fun records

let parse_args () =
  let usage_msg = "Usage: opws [OPTIONS]" in
  let usage () =
    printf "%s\n" usage_msg;
    exit 1
  in
  let home = Unix.getenv "HOME" in
  let anonargs = ref [] in
  let safe_file = ref (home ^ "/.pwsafe.psafe3") in
  let dump_all = ref false in
  let dump_title = ref "" in
  let pattern = ref ".*" in
  Arg.parse
    [ "-s", Arg.Set_string safe_file, "path Path to PSAFE3 file";
      "-d", Arg.Set dump_all, " Display all records";
      "-t", Arg.Set_string dump_title, "title Display records with this title";
      "-p", Arg.Set echo_passwords, " Echo passwords"
    ]
    (fun d -> anonargs := d :: !anonargs)
    usage_msg;
  match !anonargs with
  | [] -> !safe_file, !dump_all, !dump_title
  | _ -> usage ()

let () =
  let safe_file, dump_all, dump_title = parse_args () in
  printf "Opening database at %s\n" safe_file;
  let headers, records =
    match Prompt.read_password "Enter safe combination: " with
    | Some passphrase -> load_database safe_file passphrase
    | None -> [], []
  in
  if headers = [] || records = []
  then printf "The database is empty.\n"
  else if dump_all
  then dump_records (fun _ -> true) records
  else if dump_title <> ""
  then
    dump_records
      (fun r ->
        let rec match_title = function
          | [] -> false
          | f :: fields ->
            (match f with
            | Title title -> if dump_title = title then true else match_title fields
            | _ -> match_title fields)
        in
        match_title r)
      records
  else
    printf
      "Database OK (headers: %d, records: %d).  Run with -help for options.\n"
      (List.length headers)
      (List.length records)
