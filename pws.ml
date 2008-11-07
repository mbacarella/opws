
(* see formatv3.txt for an explanation *)

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
    mutable chan_pos: int;
    mutable block: string option;
    mutable block_pos: int option;
    cbc: Cbc.state;
  }

let make_cursor key chan chan_pos cbc =
  {
    ctx = Twofish.init key;
    chan = chan;
    chan_pos = chan_pos;
    block = None;
    block_pos = None;
    cbc = cbc
  }

let rec cursor_getchar cur =
  match cur.block, cur.block_pos with
    | None, None
    | Some _, Some 16 ->
        let bs = 16 in
        let blk = String.create bs in
        let dec = Twofish.decrypt cur.ctx in
          begin
            seek_in cur.chan cur.chan_pos;
            assert ((input cur.chan blk 0 bs) = bs);
            cur.chan_pos <- cur.chan_pos + bs;

            cur.block <- Some (Cbc.decrypt cur.cbc dec blk);
            cur.block_pos <- Some (0);
            cursor_getchar cur (* try me again *)
          end
    | Some blk, Some pos ->
        begin
          cur.block_pos <- Some (pos + 1);
          blk.[pos]
        end
    | _, _ -> failwith "read_byte: unexpected blk, pos"

let cursor_getshort cur =
  let a = cursor_getchar cur in
  let b = cursor_getchar cur in
    unpack_2bytes a b

let cursor_gets cur = function
  | 0 -> ""
  | length ->
      let b = Buffer.create length in
      let rec loop = function
        | i -> (Buffer.add_char b (cursor_getchar cur); loop (i-1))
        | 0 -> Buffer.contents b
      in
        loop length

type header =
  | Version of int
  | UUID of string
  | Non_default_preferences of string
  | Tree_display_status of string
  | Timestamp_of_last_save of int
  | Who_performed_last_save of int
  | What_performed_last_save of int
  | Last_saved_by_user of int
  | Last_saved_on_host of int
  | Database_name of string
  | Database_description of string
  | Database_filters of string
  | End_of_header

type record =
  | UUID of string
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
  | 0x00 -> Version (cursor_getshort cur)
  | 0x01 -> UUID (cursor_gets cur 16)
  | 0x02 -> Non_default_preferences
  | 0x03 -> Tree_display_status
  | 0x04 -> Timestamp_of_last_save
  | 0x05 -> Who_performed_last_save
  | 0x06 -> What_performed_last_save
  | 0x07 -> Last_saved_by_user
  | 0x08 -> Last_saved_on_host
  | 0x09 -> Database_name
  | 0x0a -> Database_description
  | 0x0b -> Database_filters
  | 0xff -> End_of_headers

let record_of_code cur length = function
  | 0x01 -> UUID (cursor_gets cur 16)
  | 0x02 -> Group
  | 0x03 -> Title
  | 0x04 -> Username
  | 0x05 -> Notes
  | 0x06 -> Password
  | 0x07 -> Creation_time
  | 0x08 -> Password_modification_time
  | 0x09 -> Last_access_time
  | 0x0a -> Password_expiry_time
  | 0x0b -> Reserved
  | 0x0c -> Last_modification_time
  | 0x0d -> URL
  | 0x0e -> Autotype
  | 0x0f -> Password_history
  | 0x10 -> Password_policy
  | 0x11 -> Password_expiry_interval
  | 0xFF -> End_of_records

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
      
let decrypt_database k l cur =
  let cbc = Cbc.init iv in
  let cur = make_cursor k ch chan cbc in
  let read_packet f =
    let a = cursor_getchar cur in
    let b = cursor_getchar cur in
    let c = cursor_getchar cur in
    let d = cursor_getchar cur in
      f (unpack_components a b c d) (cursor_getchar cur)
  in
  let rec collect_header accum = function
    | End_of_headers -> List.rev accum
    | header -> collect_header header::accum (read_packet header_of_code)
  in
  let rec collect_record accum = function
    | End_of_record -> List.rev accum
    | record -> collect_record record::accum (read_packet record_of_code)
  in
  let hdrs = collect_header [] (read_packet header_of_code) in
  let recs = collect_record [] (read_packet record_of_code) in
    (hdrs,recs)

let make_keys ch p' =
  let join ctx a b = String.concat "" [Twofish.decrypt ctx a; Twofish.decrypt ctx b] in
  let joinkeys = join (Twofish.init p') in
  let k = joinkeys ch.b1 ch.b2 in
  let l = joinkeys ch.b3 ch.b4 in
  let iv = ch.iv in
    (k, l, iv)

let load_database fn passphrase =
  let chan = open_in_gen [Open_binary] 0 fn in
  try
    let ch = load_clrtxt_header chan in
    let p' = keystretch (buffer_of_string passphrase) (buffer_of_string ch.salt) ch.iter in       
    let hofp' = Sha256.digest p' in (* hash yet another time... *)
      if (buffer_of_string ch.hofp) = hofp' then
        let (k, l, iv) = make_keys ch p' in
        let (ch, hdrs,recs) = decrypt_database k l iv ch chan in
          begin
            close_in chan;
            (ch, hdrs, recs)
              end
      else
        begin
          Printf.printf "Passphrase incorrect.\n";
          close_in chan;
          exit 1
        end
  with
    | Sys_error fn -> failwith ("load_database: error accessing " ^ fn)
    | End_of_file -> failwith ("load_database: "^fn^": corrupted database (EOF reached unexpectedly)")

let () =
  let fn = "/home/mbacarella/.pwsafe.psafe3" in
    Printf.printf "Opening database at %s\n" fn;
    match Prompt.read_password () with
      | Some passphrase -> load_database fn passphrase
      | None -> ()
  ()
