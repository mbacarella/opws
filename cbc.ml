
type state =
    {
      mutable prev_v: string;
    }

let init iv =
  {
    prev_v = iv;
  }

let chr x = char_of_int x
let int c = int_of_char c

let xor_strings b c =
  let a = String.copy b in
  begin
    for i = 0 to (String.length a)-1 do
      a.[i] <- chr((int b.[i]) lxor (int c.[i]))
    done;
    a
  end
    
let encrypt cbc enc p =
  let p' = xor_strings p cbc.prev_v in
  let c = enc p' in
    (cbc.prev_v <- c; c)
      
let decrypt cbc dec c =
  let p = dec c in
  let p' = xor_strings p cbc.prev_v in
    (cbc.prev_v <- c; p')
