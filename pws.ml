
open Printf

(* see formatv3.txt for some answers *)

type clear_header =
  {
    tag: string;
    salt: string;
    iter: int;
    hofp: string;
    b1: string;
    b2: string;
    b3: string;
    b4: string;
    iv: string;
  }

type database_cursor =
  {
    ctx: Twofish.ctx;
    chan: in_channel;
    chan_start: int;
    mutable chan_pos: int;
    mutable block: string option;
    mutable block_pos: int option;
    cbc: Cbc.state;
  }

exception End_of_database

let cursor_nextblock cur =
  let blocksize = 16 in

  (* find start of next block *)
  assert ((cur.chan_pos mod blocksize) = 0);

  (* read the block *)
  seek_in cur.chan (cur.chan_start + cur.chan_pos);  

  let block = String.create blocksize in
  let dec = Twofish.decrypt cur.ctx in
  really_input cur.chan block 0 blocksize;
  if block = "PWS3-EOFPWS3-EOF" then
    raise End_of_database
  else
    begin
      cur.block <- Some (Cbc.decrypt cur.cbc dec block);
      cur.block_pos <- Some 0;
        (* get in position for the next call *)
      cur.chan_pos <- cur.chan_pos + blocksize;
    end

let rec cursor_getchar cur =
  match cur.block, cur.block_pos with
    | None, None
    | Some _, Some 16 ->
        cursor_nextblock cur;
        cursor_getchar cur
    | Some blk, Some pos ->
        begin
          cur.block_pos <- Some (pos + 1);
          blk.[pos]
        end
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
        | i -> (Buffer.add_char b (cursor_getchar cur); loop (i-1))
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
  | End_of_entry

let header_of_code cur length = function
  | 0x00 -> (assert (length = 2); Version (cursor_getshort cur))
  | 0x01 -> (assert (length = 16); Header_UUID (cursor_gets cur 16))
  | 0x02 -> Non_default_preferences (cursor_gets cur length)
  | 0x03 -> Tree_display_status (cursor_gets cur length)
  | 0x04 -> (assert (length = 8); Timestamp_of_last_save (cursor_gettime cur))
  | 0x05 -> Who_performed_last_save (cursor_gets cur length)
  | 0x06 -> What_performed_last_save (cursor_gets cur length)
  | 0x07 -> Last_saved_by_user (cursor_gets cur length)
  | 0x08 -> Last_saved_on_host (cursor_gets cur length)
  | 0x09 -> Database_name (cursor_gets cur length)
  | 0x0a -> Database_description (cursor_gets cur length)
  | 0x0b -> Database_filters (cursor_gets cur length)
  | 0xff -> End_of_header
  | code -> (failwith ("header_of_code: unknown code: "^(string_of_int code)))

let entry_of_code cur length = function
  | 0x01 -> (assert (length = 16); Record_UUID (cursor_gets cur 16))
  | 0x02 -> Group (cursor_gets cur length)
  | 0x03 -> Title (cursor_gets cur length)
  | 0x04 -> Username (cursor_gets cur length)
  | 0x05 -> Notes (cursor_gets cur length)
  | 0x06 -> Password (cursor_gets cur length)
  | 0x07 -> (assert (length = 4); Creation_time (cursor_gettime cur))
  | 0x08 -> (assert (length = 4); Password_modification_time (cursor_gettime cur))
  | 0x09 -> (assert (length = 4); Last_access_time (cursor_gettime cur))
  | 0x0a -> (assert (length = 4); Password_expiry_time (cursor_gettime cur))
  | 0x0b -> (assert (length = 4); Reserved (cursor_gets cur 4))
  | 0x0c -> (assert (length = 4); Last_modification_time (cursor_gettime cur))
  | 0x0d -> URL (cursor_gets cur length)
  | 0x0e -> Autotype (cursor_gets cur length)
  | 0x0f -> Password_history (cursor_gets cur length)
  | 0x10 -> Password_policy (cursor_gets cur length)
  | 0x11 -> (assert (length = 2); Password_expiry_interval (cursor_getshort cur))
  | 0xFF -> End_of_entry
  | code -> (failwith ("entry_of_code: unknown code: "^(string_of_int code)))


(*
 KEYSTRETCH/hash implementation as specified here:
   http://www.cs.berkeley.edu/~daw/papers/keystretch.ps
*)

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
    | (_,_) -> raise (Invalid_argument
			            "in_bits: off and bits must be multiples of 8")
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
      
let decrypt_database k l ch chan =
  let cbc = Cbc.init ch.iv in
  let cur =
    {
      ctx = Twofish.init k;
      chan = chan;
      chan_start = 152;
      chan_pos = 0;
      block = None;
      block_pos = None;
      cbc = cbc
    }
  in
  let read_field f cur =
    cursor_nextblock cur;
    let a = cursor_getchar cur in
    let b = cursor_getchar cur in
    let c = cursor_getchar cur in
    let d = cursor_getchar cur in
    let x = (Bin.unpack32_le (sprintf "%c%c%c%c" a b c d)) in
    let code = int_of_char (cursor_getchar cur) in
    begin
      printf "length: %d, code: %d\n" x code;
      f cur x code
    end
  in
  let next_header_field = read_field header_of_code in
  let next_entry_field = read_field entry_of_code in

  let rec collect_headers cur accum = function
    | End_of_header -> List.rev accum
    | header ->
        collect_headers cur (header::accum) (next_header_field cur)
  in
  let rec collect_entries cur accum = function
    | End_of_entry -> List.rev accum
    | record ->
        collect_entries cur (record::accum) (next_entry_field cur)
  in
  let rec collect_database cur accum =
    let entries = 
      try
        collect_entries cur [] (next_entry_field cur)
      with
      | End_of_database -> List.rev accum
    in
    collect_database cur (entries @ accum)
  in
  let headers = collect_headers cur [] (next_header_field cur) in
  let database = collect_database cur [] in
  headers, database

let make_keys ch p' =
  let join ctx a b =
    let a' = Twofish.decrypt ctx a in
    let b' = Twofish.decrypt ctx b in
    String.concat "" [a'; b'] in
  let joinkeys = join (Twofish.init p') in
  let k = joinkeys ch.b1 ch.b2 in
  let l = joinkeys ch.b3 ch.b4 in
  let iv = ch.iv in
  (k, l, iv)

let load_database fn passphrase =
  let chan = open_in_gen [Open_binary] 0 fn in
  try
    let ch = load_clrtxt_header chan in
    let b_passphrase = buffer_of_string passphrase in
    let b_salt = buffer_of_string ch.salt in 
    let p' = keystretch b_passphrase b_salt ch.iter in       
    let hofp' = Sha256.digest p' in
    if (buffer_of_string ch.hofp) = hofp' then
      let (k, l, iv) = make_keys ch (Buffer.contents p') in
      let hdrs,recs = decrypt_database k l ch chan in
      begin
        close_in chan;
        hdrs, recs
      end
    else
      begin
        printf "Passphrase incorrect.\n";
        close_in chan;
        exit 1
      end
  with
  | Sys_error fn -> failwith ("load_database: error accessing " ^ fn)
  | End_of_file -> failwith ("load_database: "
		                     ^fn^": corrupted database (EOF reached unexpectedly)")
      
let parse_args () =
  let usage_msg = "Usage: pwsafe [OPTIONS]" in
  let usage () =
    printf "%s\n" usage_msg;
    exit 1
  in
  let anonargs = ref [] in
  let safe = ref "/home/mbacarella/.pwsafe.psafe3" in
  let speclist = [
    ("-s", Arg.Set_string safe, "path Path to password safe file")
  ]
  in
  Arg.parse speclist (fun d -> anonargs := d :: !anonargs) usage_msg;
    match !anonargs with
    | [] -> !safe
    | _ -> usage ()
        
let () =
  let fn = parse_args () in
  printf "Opening database at %s\n" fn;
  let hdrs, recs =
    match Prompt.read_password "Enter safe combination: " with
	| Some passphrase -> load_database fn passphrase
	| None -> [], []
  in
  if (hdrs = []) || (recs = []) then
	printf "empty database!\n"
  else
	printf "headers: %d, records: %d\n"
	  (List.length hdrs) (List.length recs)
