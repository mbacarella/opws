(* A CBC abstraction layer
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

type state = { mutable prev_v : bytes }

let init iv = { prev_v = iv }

let xor_strings b c =
  let int c = int_of_char c in
  let a = Bytes.copy b in
  for i = 0 to Bytes.length a - 1 do
    Bytes.set a i (Bin.chr (int (Bytes.get b i) lxor int (Bytes.get c i)))
  done;
  a

let encrypt cbc enc p =
  let p' = xor_strings p cbc.prev_v in
  let c = enc p' in
  cbc.prev_v <- c;
  c

let decrypt cbc dec c =
  let p = dec c in
  let p' = xor_strings p cbc.prev_v in
  cbc.prev_v <- c;
  p'
