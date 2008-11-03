
(*
    SHA256 as specified here:
    http://en.wikipedia.org/wiki/SHA256
*)

type ctx =
    {
      mutable total_length: Int64.t;
      mutable h: Int32.t array;
    }

let add_int32 x y = Int32.add x y
let add_int64 x y = Int64.add x y

let left_int32 x n = Int32.shift_left x n
let right_int32 x n = Int32.shift_right_logical x n
let or_int32 x y = Int32.logor x y
let xor_int32 x y = Int32.logxor x y
let and_int32 x y = Int32.logand x y
let not_int32 x = Int32.lognot x

let rotate x n = (or_int32 (right_int32 x n) (left_int32 x (32 - n)))
let shift x n = right_int32 x n
let ch x y z = xor_int32 (and_int32 x y) (and_int32 (not_int32 x) z)
let maj x y z = (xor_int32 (and_int32 x y) (xor_int32 (and_int32 x z) (and_int32 y z)))
let sum0 x = (xor_int32 (rotate x  2) (xor_int32 (rotate x 13) (rotate x 22)))
let sum1 x = (xor_int32 (rotate x  6) (xor_int32 (rotate x 11) (rotate x 25)))
let rh00 x = (xor_int32 (rotate x  7) (xor_int32 (rotate x 18) (shift  x  3)))
let rh01 x = (xor_int32 (rotate x 17) (xor_int32 (rotate x 19) (shift  x 10)))
let to_int32 x = (Int32.of_int (int_of_char x))
 
let as_bytes bits =
  match (bits mod 8) with
    | 0 -> (bits / 8)
    | _ -> failwith "as_bytes: bits must be multiple of 8"
let as_bits bytes = bytes * 8

let bs_in_bits = 512
let bs_in_bytes = (as_bytes 512)

let k = [|
  0x428a2f98l; 0x71374491l; 0xb5c0fbcfl; 0xe9b5dba5l;
  0x3956c25bl; 0x59f111f1l; 0x923f82a4l; 0xab1c5ed5l;
  0xd807aa98l; 0x12835b01l; 0x243185bel; 0x550c7dc3l;
  0x72be5d74l; 0x80deb1fel; 0x9bdc06a7l; 0xc19bf174l;
  0xe49b69c1l; 0xefbe4786l; 0x0fc19dc6l; 0x240ca1ccl;
  0x2de92c6fl; 0x4a7484aal; 0x5cb0a9dcl; 0x76f988dal;
  0x983e5152l; 0xa831c66dl; 0xb00327c8l; 0xbf597fc7l;
  0xc6e00bf3l; 0xd5a79147l; 0x06ca6351l; 0x14292967l;
  0x27b70a85l; 0x2e1b2138l; 0x4d2c6dfcl; 0x53380d13l;
  0x650a7354l; 0x766a0abbl; 0x81c2c92el; 0x92722c85l;
  0xa2bfe8a1l; 0xa81a664bl; 0xc24b8b70l; 0xc76c51a3l;
  0xd192e819l; 0xd6990624l; 0xf40e3585l; 0x106aa070l;
  0x19a4c116l; 0x1e376c08l; 0x2748774cl; 0x34b0bcb5l;
  0x391c0cb3l; 0x4ed8aa4al; 0x5b9cca4fl; 0x682e6ff3l;
  0x748f82eel; 0x78a5636fl; 0x84c87814l; 0x8cc70208l;
  0x90befffal; 0xa4506cebl; 0xbef9a3f7l; 0xc67178f2l
|]

let init () =
  {
    total_length = 0L;
    h = [|
      0x6a09e667l;
      0xbb67ae85l;
      0x3c6ef372l;
      0xa54ff53al;
      0x510e527fl;
      0x9b05688cl;
      0x1f83d9abl;
      0x5be0cd19l
    |];
  }

let update ctx message =
  let sha = ctx.h in
  let message_bits = as_bits (Buffer.length message) in
    if message_bits <> bs_in_bits then
      failwith ("update: message must be 512 bits; got "
                ^(string_of_int message_bits)^" bits")
    else
      let w = Array.make bs_in_bytes 0l in
        begin
          for t = 0 to 15 do
            w.(t) <- (or_int32 (left_int32 (to_int32 (Buffer.nth message (t*4  ))) 24)
                     (or_int32 (left_int32 (to_int32 (Buffer.nth message (t*4+1))) 16)
                     (or_int32 (left_int32 (to_int32 (Buffer.nth message (t*4+2)))  8)
                                           (to_int32 (Buffer.nth message (t*4+3)))   )));
          done;
          for t = 16 to 63 do
            w.(t) <- add_int32 (add_int32 (rh01 w.(t-2)) w.(t-7)) (add_int32 (rh00 w.(t-15)) w.(t-16))
          done;
          let tem = [| 0l; 0l |] in
          let a = ref sha.(0) in 
          let b = ref sha.(1) in
          let c = ref sha.(2) in
          let d = ref sha.(3) in 
          let e = ref sha.(4) in
          let f = ref sha.(5) in
          let g = ref sha.(6) in
          let h = ref sha.(7) in
            for t = 0 to 63 do
              begin
                tem.(0) <- add_int32 (add_int32 !h (sum1 !e)) (add_int32 (ch !e !f !g) (add_int32 k.(t) w.(t)));
                tem.(1) <- add_int32 (sum0 !a) (maj !a !b !c);
                h := !g;
                g := !f;
                f := !e;
                e := add_int32 !d tem.(0);
                d := !c;
                c := !b;
                b := !a;
                a := add_int32 tem.(0) tem.(1);
              end
            done;
            sha.(0) <- add_int32 sha.(0) !a;
            sha.(1) <- add_int32 sha.(1) !b;
            sha.(2) <- add_int32 sha.(2) !c;
            sha.(3) <- add_int32 sha.(3) !d;
            sha.(4) <- add_int32 sha.(4) !e;
            sha.(5) <- add_int32 sha.(5) !f;
            sha.(6) <- add_int32 sha.(6) !g;
            sha.(7) <- add_int32 sha.(7) !h;
            
            (* good faith attempt to clear memory *)
            for i = 0 to 63 do w.(i) <- 0l done;
            tem.(0) <- 0l; tem.(1) <- 0l;
            a := 0l; b := 0l; c := 0l; d := 0l; e := 0l; f := 0l; g := 0l; h := 0l;
            ctx.total_length <- (add_int64 ctx.total_length (Int64.of_int message_bits));
        end

let sub_buf b pos len =
  let s = Buffer.sub b pos len in
  let b' = Buffer.create ( String.length s) in
    (Buffer.add_string b' s; b')

let hexdigits64 m =
  let rec hexdigits_inner hx i =
    match i with
      | 64 -> hx
      | _ -> hexdigits_inner (hx ^ (Printf.sprintf "%02x" (int_of_char (Buffer.nth m i)))) (i+1)
  in
    hexdigits_inner "" 0

let pack_sha256 ctx =
  let h = ctx.h in
  let sha256 = Buffer.create (as_bytes 256) in
  let rec pack_sha256_inner = function 
    | 8 -> sha256
    | i -> (Buffer.add_buffer sha256 (Bin.pack32 h.(i)); pack_sha256_inner (i+1))
  in
    pack_sha256_inner 0

let final ctx message =
  let original_length = as_bits (Buffer.length message) in
    if original_length > bs_in_bits then
      failwith ("error: final: must be called with message smaller than 512 bits;"
                  ^"  got "^ (string_of_int original_length)^" bits")
    else
      let pad_blocks = if (original_length mod bs_in_bits) < 448 then 1 else 2 in
        ctx.total_length <- (add_int64 ctx.total_length (Int64.of_int original_length));
        Buffer.add_char message '\x80';
        let pad_start = as_bits (Buffer.length message) in
        let message_length = ((original_length / bs_in_bits) + pad_blocks) * bs_in_bits in
          begin (* appending k bits of 0 (where message_length-64 is our k) *)
            for i = as_bytes pad_start to (as_bytes (message_length - (as_bytes 64)))-8 do
              Buffer.add_char message '\x00'
            done;
            Buffer.add_buffer message (Bin.pack64 ctx.total_length);
            let new_length = as_bits (Buffer.length message) in
              if new_length = 1024 then
                begin
                  update ctx (sub_buf message 0 bs_in_bytes);
                  update ctx (sub_buf message bs_in_bytes bs_in_bytes)
                end
              else if new_length = 512 then
                begin
                  update ctx message
                end
              else
                failwith ("error: final: unexpected length "^(string_of_int new_length));
          end
            
let digest message =
  let message_length = as_bits (Buffer.length message) in
  let ctx = init () in
  let total_blocks = (message_length/bs_in_bits) in
  let last_block_pos = (total_blocks * bs_in_bytes) in
  let last_block_len = as_bytes (message_length)-last_block_pos in
    for blockno = 0 to total_blocks-1 do
      update ctx (sub_buf message (blockno * bs_in_bytes) bs_in_bytes);
    done;
    final ctx (sub_buf message last_block_pos last_block_len);
    pack_sha256 ctx
      
let hexdigits m =
  let rec hexdigits_inner hx = function
    | 32 -> hx
    | i -> hexdigits_inner (hx ^ (Printf.sprintf "%02x" (int_of_char (Buffer.nth m i)))) (i+1)
  in
    hexdigits_inner "" 0

let hexdigest s =
  let b = Buffer.create (String.length s) in
    (Buffer.add_string b s; hexdigits (digest b))

let test () =
  let rec run_tests = function
    | [] -> ()
    | (msg,sum) :: tests ->
        let result = (hexdigest msg) in
        if result = sum then
          Printf.printf "ok: sha256('%s') = '%s'\n" msg sum
        else
          Printf.printf "FAIL: sha256('%s') != '%s'; got '%s'\n" msg sum result;
          run_tests tests
  in run_tests [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ("def", "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34");
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    ("The quick brown fox jumps over the lazy cog", "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be");
    ("abcabcabc", "76b99ab4be8521d78b19bcff7d1078aabeb477bd134f404094c92cd39f051c3e");
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34");
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "6bc3b8eaea5380e522ff7df7736989b5e3fff569ba75003be63a8e7ab9c8123e");
  ]

(*
let () = test ()
*)
