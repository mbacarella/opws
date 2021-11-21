(* An implementation of the Twofish block cipher in OCaml
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

   The algorithm below has been implemented using Guido Flohr's
   CPAN Crypt::Twofish_PP as a reference.  Any flaws in this program
   are, however, my own fault.
*)

open Bin

let ( << ) x y = left32 x y
let ( >> ) x y = right32 x y
let ( & ) x y = and32 x y

(* ^ is more useful as a 32-bit XOR than it is as a string-concat *)
let ( ^^ ) = ( ^ )
let ( ^ ) x y = xor32 x y

type ctx =
  { k : Int32.t array;
    s : Int32.t array array (* s-boxes *)
  }

let q0 =
  [| 0xA9;
     0x67;
     0xB3;
     0xE8;
     0x04;
     0xFD;
     0xA3;
     0x76;
     0x9A;
     0x92;
     0x80;
     0x78;
     0xE4;
     0xDD;
     0xD1;
     0x38;
     0x0D;
     0xC6;
     0x35;
     0x98;
     0x18;
     0xF7;
     0xEC;
     0x6C;
     0x43;
     0x75;
     0x37;
     0x26;
     0xFA;
     0x13;
     0x94;
     0x48;
     0xF2;
     0xD0;
     0x8B;
     0x30;
     0x84;
     0x54;
     0xDF;
     0x23;
     0x19;
     0x5B;
     0x3D;
     0x59;
     0xF3;
     0xAE;
     0xA2;
     0x82;
     0x63;
     0x01;
     0x83;
     0x2E;
     0xD9;
     0x51;
     0x9B;
     0x7C;
     0xA6;
     0xEB;
     0xA5;
     0xBE;
     0x16;
     0x0C;
     0xE3;
     0x61;
     0xC0;
     0x8C;
     0x3A;
     0xF5;
     0x73;
     0x2C;
     0x25;
     0x0B;
     0xBB;
     0x4E;
     0x89;
     0x6B;
     0x53;
     0x6A;
     0xB4;
     0xF1;
     0xE1;
     0xE6;
     0xBD;
     0x45;
     0xE2;
     0xF4;
     0xB6;
     0x66;
     0xCC;
     0x95;
     0x03;
     0x56;
     0xD4;
     0x1C;
     0x1E;
     0xD7;
     0xFB;
     0xC3;
     0x8E;
     0xB5;
     0xE9;
     0xCF;
     0xBF;
     0xBA;
     0xEA;
     0x77;
     0x39;
     0xAF;
     0x33;
     0xC9;
     0x62;
     0x71;
     0x81;
     0x79;
     0x09;
     0xAD;
     0x24;
     0xCD;
     0xF9;
     0xD8;
     0xE5;
     0xC5;
     0xB9;
     0x4D;
     0x44;
     0x08;
     0x86;
     0xE7;
     0xA1;
     0x1D;
     0xAA;
     0xED;
     0x06;
     0x70;
     0xB2;
     0xD2;
     0x41;
     0x7B;
     0xA0;
     0x11;
     0x31;
     0xC2;
     0x27;
     0x90;
     0x20;
     0xF6;
     0x60;
     0xFF;
     0x96;
     0x5C;
     0xB1;
     0xAB;
     0x9E;
     0x9C;
     0x52;
     0x1B;
     0x5F;
     0x93;
     0x0A;
     0xEF;
     0x91;
     0x85;
     0x49;
     0xEE;
     0x2D;
     0x4F;
     0x8F;
     0x3B;
     0x47;
     0x87;
     0x6D;
     0x46;
     0xD6;
     0x3E;
     0x69;
     0x64;
     0x2A;
     0xCE;
     0xCB;
     0x2F;
     0xFC;
     0x97;
     0x05;
     0x7A;
     0xAC;
     0x7F;
     0xD5;
     0x1A;
     0x4B;
     0x0E;
     0xA7;
     0x5A;
     0x28;
     0x14;
     0x3F;
     0x29;
     0x88;
     0x3C;
     0x4C;
     0x02;
     0xB8;
     0xDA;
     0xB0;
     0x17;
     0x55;
     0x1F;
     0x8A;
     0x7D;
     0x57;
     0xC7;
     0x8D;
     0x74;
     0xB7;
     0xC4;
     0x9F;
     0x72;
     0x7E;
     0x15;
     0x22;
     0x12;
     0x58;
     0x07;
     0x99;
     0x34;
     0x6E;
     0x50;
     0xDE;
     0x68;
     0x65;
     0xBC;
     0xDB;
     0xF8;
     0xC8;
     0xA8;
     0x2B;
     0x40;
     0xDC;
     0xFE;
     0x32;
     0xA4;
     0xCA;
     0x10;
     0x21;
     0xF0;
     0xD3;
     0x5D;
     0x0F;
     0x00;
     0x6F;
     0x9D;
     0x36;
     0x42;
     0x4A;
     0x5E;
     0xC1;
     0xE0
  |]

let q1 =
  [| 0x75;
     0xF3;
     0xC6;
     0xF4;
     0xDB;
     0x7B;
     0xFB;
     0xC8;
     0x4A;
     0xD3;
     0xE6;
     0x6B;
     0x45;
     0x7D;
     0xE8;
     0x4B;
     0xD6;
     0x32;
     0xD8;
     0xFD;
     0x37;
     0x71;
     0xF1;
     0xE1;
     0x30;
     0x0F;
     0xF8;
     0x1B;
     0x87;
     0xFA;
     0x06;
     0x3F;
     0x5E;
     0xBA;
     0xAE;
     0x5B;
     0x8A;
     0x00;
     0xBC;
     0x9D;
     0x6D;
     0xC1;
     0xB1;
     0x0E;
     0x80;
     0x5D;
     0xD2;
     0xD5;
     0xA0;
     0x84;
     0x07;
     0x14;
     0xB5;
     0x90;
     0x2C;
     0xA3;
     0xB2;
     0x73;
     0x4C;
     0x54;
     0x92;
     0x74;
     0x36;
     0x51;
     0x38;
     0xB0;
     0xBD;
     0x5A;
     0xFC;
     0x60;
     0x62;
     0x96;
     0x6C;
     0x42;
     0xF7;
     0x10;
     0x7C;
     0x28;
     0x27;
     0x8C;
     0x13;
     0x95;
     0x9C;
     0xC7;
     0x24;
     0x46;
     0x3B;
     0x70;
     0xCA;
     0xE3;
     0x85;
     0xCB;
     0x11;
     0xD0;
     0x93;
     0xB8;
     0xA6;
     0x83;
     0x20;
     0xFF;
     0x9F;
     0x77;
     0xC3;
     0xCC;
     0x03;
     0x6F;
     0x08;
     0xBF;
     0x40;
     0xE7;
     0x2B;
     0xE2;
     0x79;
     0x0C;
     0xAA;
     0x82;
     0x41;
     0x3A;
     0xEA;
     0xB9;
     0xE4;
     0x9A;
     0xA4;
     0x97;
     0x7E;
     0xDA;
     0x7A;
     0x17;
     0x66;
     0x94;
     0xA1;
     0x1D;
     0x3D;
     0xF0;
     0xDE;
     0xB3;
     0x0B;
     0x72;
     0xA7;
     0x1C;
     0xEF;
     0xD1;
     0x53;
     0x3E;
     0x8F;
     0x33;
     0x26;
     0x5F;
     0xEC;
     0x76;
     0x2A;
     0x49;
     0x81;
     0x88;
     0xEE;
     0x21;
     0xC4;
     0x1A;
     0xEB;
     0xD9;
     0xC5;
     0x39;
     0x99;
     0xCD;
     0xAD;
     0x31;
     0x8B;
     0x01;
     0x18;
     0x23;
     0xDD;
     0x1F;
     0x4E;
     0x2D;
     0xF9;
     0x48;
     0x4F;
     0xF2;
     0x65;
     0x8E;
     0x78;
     0x5C;
     0x58;
     0x19;
     0x8D;
     0xE5;
     0x98;
     0x57;
     0x67;
     0x7F;
     0x05;
     0x64;
     0xAF;
     0x63;
     0xB6;
     0xFE;
     0xF5;
     0xB7;
     0x3C;
     0xA5;
     0xCE;
     0xE9;
     0x68;
     0x44;
     0xE0;
     0x4D;
     0x43;
     0x69;
     0x29;
     0x2E;
     0xAC;
     0x15;
     0x59;
     0xA8;
     0x0A;
     0x9E;
     0x6E;
     0x47;
     0xDF;
     0x34;
     0x35;
     0x6A;
     0xCF;
     0xDC;
     0x22;
     0xC9;
     0xC0;
     0x9B;
     0x89;
     0xD4;
     0xED;
     0xAB;
     0x12;
     0xA2;
     0x0D;
     0x52;
     0xBB;
     0x02;
     0x2F;
     0xA9;
     0xD7;
     0x61;
     0x1E;
     0xB4;
     0x50;
     0x04;
     0xF6;
     0xC2;
     0x16;
     0x25;
     0x86;
     0x56;
     0x55;
     0x09;
     0xBE;
     0x91
  |]

let m0 =
  [| 0xBCBC3275l;
     0xECEC21F3l;
     0x202043C6l;
     0xB3B3C9F4l;
     0xDADA03DBl;
     0x02028B7Bl;
     0xE2E22BFBl;
     0x9E9EFAC8l;
     0xC9C9EC4Al;
     0xD4D409D3l;
     0x18186BE6l;
     0x1E1E9F6Bl;
     0x98980E45l;
     0xB2B2387Dl;
     0xA6A6D2E8l;
     0x2626B74Bl;
     0x3C3C57D6l;
     0x93938A32l;
     0x8282EED8l;
     0x525298FDl;
     0x7B7BD437l;
     0xBBBB3771l;
     0x5B5B97F1l;
     0x474783E1l;
     0x24243C30l;
     0x5151E20Fl;
     0xBABAC6F8l;
     0x4A4AF31Bl;
     0xBFBF4887l;
     0x0D0D70FAl;
     0xB0B0B306l;
     0x7575DE3Fl;
     0xD2D2FD5El;
     0x7D7D20BAl;
     0x666631AEl;
     0x3A3AA35Bl;
     0x59591C8Al;
     0x00000000l;
     0xCDCD93BCl;
     0x1A1AE09Dl;
     0xAEAE2C6Dl;
     0x7F7FABC1l;
     0x2B2BC7B1l;
     0xBEBEB90El;
     0xE0E0A080l;
     0x8A8A105Dl;
     0x3B3B52D2l;
     0x6464BAD5l;
     0xD8D888A0l;
     0xE7E7A584l;
     0x5F5FE807l;
     0x1B1B1114l;
     0x2C2CC2B5l;
     0xFCFCB490l;
     0x3131272Cl;
     0x808065A3l;
     0x73732AB2l;
     0x0C0C8173l;
     0x79795F4Cl;
     0x6B6B4154l;
     0x4B4B0292l;
     0x53536974l;
     0x94948F36l;
     0x83831F51l;
     0x2A2A3638l;
     0xC4C49CB0l;
     0x2222C8BDl;
     0xD5D5F85Al;
     0xBDBDC3FCl;
     0x48487860l;
     0xFFFFCE62l;
     0x4C4C0796l;
     0x4141776Cl;
     0xC7C7E642l;
     0xEBEB24F7l;
     0x1C1C1410l;
     0x5D5D637Cl;
     0x36362228l;
     0x6767C027l;
     0xE9E9AF8Cl;
     0x4444F913l;
     0x1414EA95l;
     0xF5F5BB9Cl;
     0xCFCF18C7l;
     0x3F3F2D24l;
     0xC0C0E346l;
     0x7272DB3Bl;
     0x54546C70l;
     0x29294CCAl;
     0xF0F035E3l;
     0x0808FE85l;
     0xC6C617CBl;
     0xF3F34F11l;
     0x8C8CE4D0l;
     0xA4A45993l;
     0xCACA96B8l;
     0x68683BA6l;
     0xB8B84D83l;
     0x38382820l;
     0xE5E52EFFl;
     0xADAD569Fl;
     0x0B0B8477l;
     0xC8C81DC3l;
     0x9999FFCCl;
     0x5858ED03l;
     0x19199A6Fl;
     0x0E0E0A08l;
     0x95957EBFl;
     0x70705040l;
     0xF7F730E7l;
     0x6E6ECF2Bl;
     0x1F1F6EE2l;
     0xB5B53D79l;
     0x09090F0Cl;
     0x616134AAl;
     0x57571682l;
     0x9F9F0B41l;
     0x9D9D803Al;
     0x111164EAl;
     0x2525CDB9l;
     0xAFAFDDE4l;
     0x4545089Al;
     0xDFDF8DA4l;
     0xA3A35C97l;
     0xEAEAD57El;
     0x353558DAl;
     0xEDEDD07Al;
     0x4343FC17l;
     0xF8F8CB66l;
     0xFBFBB194l;
     0x3737D3A1l;
     0xFAFA401Dl;
     0xC2C2683Dl;
     0xB4B4CCF0l;
     0x32325DDEl;
     0x9C9C71B3l;
     0x5656E70Bl;
     0xE3E3DA72l;
     0x878760A7l;
     0x15151B1Cl;
     0xF9F93AEFl;
     0x6363BFD1l;
     0x3434A953l;
     0x9A9A853El;
     0xB1B1428Fl;
     0x7C7CD133l;
     0x88889B26l;
     0x3D3DA65Fl;
     0xA1A1D7ECl;
     0xE4E4DF76l;
     0x8181942Al;
     0x91910149l;
     0x0F0FFB81l;
     0xEEEEAA88l;
     0x161661EEl;
     0xD7D77321l;
     0x9797F5C4l;
     0xA5A5A81Al;
     0xFEFE3FEBl;
     0x6D6DB5D9l;
     0x7878AEC5l;
     0xC5C56D39l;
     0x1D1DE599l;
     0x7676A4CDl;
     0x3E3EDCADl;
     0xCBCB6731l;
     0xB6B6478Bl;
     0xEFEF5B01l;
     0x12121E18l;
     0x6060C523l;
     0x6A6AB0DDl;
     0x4D4DF61Fl;
     0xCECEE94El;
     0xDEDE7C2Dl;
     0x55559DF9l;
     0x7E7E5A48l;
     0x2121B24Fl;
     0x03037AF2l;
     0xA0A02665l;
     0x5E5E198El;
     0x5A5A6678l;
     0x65654B5Cl;
     0x62624E58l;
     0xFDFD4519l;
     0x0606F48Dl;
     0x404086E5l;
     0xF2F2BE98l;
     0x3333AC57l;
     0x17179067l;
     0x05058E7Fl;
     0xE8E85E05l;
     0x4F4F7D64l;
     0x89896AAFl;
     0x10109563l;
     0x74742FB6l;
     0x0A0A75FEl;
     0x5C5C92F5l;
     0x9B9B74B7l;
     0x2D2D333Cl;
     0x3030D6A5l;
     0x2E2E49CEl;
     0x494989E9l;
     0x46467268l;
     0x77775544l;
     0xA8A8D8E0l;
     0x9696044Dl;
     0x2828BD43l;
     0xA9A92969l;
     0xD9D97929l;
     0x8686912El;
     0xD1D187ACl;
     0xF4F44A15l;
     0x8D8D1559l;
     0xD6D682A8l;
     0xB9B9BC0Al;
     0x42420D9El;
     0xF6F6C16El;
     0x2F2FB847l;
     0xDDDD06DFl;
     0x23233934l;
     0xCCCC6235l;
     0xF1F1C46Al;
     0xC1C112CFl;
     0x8585EBDCl;
     0x8F8F9E22l;
     0x7171A1C9l;
     0x9090F0C0l;
     0xAAAA539Bl;
     0x0101F189l;
     0x8B8BE1D4l;
     0x4E4E8CEDl;
     0x8E8E6FABl;
     0xABABA212l;
     0x6F6F3EA2l;
     0xE6E6540Dl;
     0xDBDBF252l;
     0x92927BBBl;
     0xB7B7B602l;
     0x6969CA2Fl;
     0x3939D9A9l;
     0xD3D30CD7l;
     0xA7A72361l;
     0xA2A2AD1El;
     0xC3C399B4l;
     0x6C6C4450l;
     0x07070504l;
     0x04047FF6l;
     0x272746C2l;
     0xACACA716l;
     0xD0D07625l;
     0x50501386l;
     0xDCDCF756l;
     0x84841A55l;
     0xE1E15109l;
     0x7A7A25BEl;
     0x1313EF91l
  |]

let m1 =
  [| 0xA9D93939l;
     0x67901717l;
     0xB3719C9Cl;
     0xE8D2A6A6l;
     0x04050707l;
     0xFD985252l;
     0xA3658080l;
     0x76DFE4E4l;
     0x9A084545l;
     0x92024B4Bl;
     0x80A0E0E0l;
     0x78665A5Al;
     0xE4DDAFAFl;
     0xDDB06A6Al;
     0xD1BF6363l;
     0x38362A2Al;
     0x0D54E6E6l;
     0xC6432020l;
     0x3562CCCCl;
     0x98BEF2F2l;
     0x181E1212l;
     0xF724EBEBl;
     0xECD7A1A1l;
     0x6C774141l;
     0x43BD2828l;
     0x7532BCBCl;
     0x37D47B7Bl;
     0x269B8888l;
     0xFA700D0Dl;
     0x13F94444l;
     0x94B1FBFBl;
     0x485A7E7El;
     0xF27A0303l;
     0xD0E48C8Cl;
     0x8B47B6B6l;
     0x303C2424l;
     0x84A5E7E7l;
     0x54416B6Bl;
     0xDF06DDDDl;
     0x23C56060l;
     0x1945FDFDl;
     0x5BA33A3Al;
     0x3D68C2C2l;
     0x59158D8Dl;
     0xF321ECECl;
     0xAE316666l;
     0xA23E6F6Fl;
     0x82165757l;
     0x63951010l;
     0x015BEFEFl;
     0x834DB8B8l;
     0x2E918686l;
     0xD9B56D6Dl;
     0x511F8383l;
     0x9B53AAAAl;
     0x7C635D5Dl;
     0xA63B6868l;
     0xEB3FFEFEl;
     0xA5D63030l;
     0xBE257A7Al;
     0x16A7ACACl;
     0x0C0F0909l;
     0xE335F0F0l;
     0x6123A7A7l;
     0xC0F09090l;
     0x8CAFE9E9l;
     0x3A809D9Dl;
     0xF5925C5Cl;
     0x73810C0Cl;
     0x2C273131l;
     0x2576D0D0l;
     0x0BE75656l;
     0xBB7B9292l;
     0x4EE9CECEl;
     0x89F10101l;
     0x6B9F1E1El;
     0x53A93434l;
     0x6AC4F1F1l;
     0xB499C3C3l;
     0xF1975B5Bl;
     0xE1834747l;
     0xE66B1818l;
     0xBDC82222l;
     0x450E9898l;
     0xE26E1F1Fl;
     0xF4C9B3B3l;
     0xB62F7474l;
     0x66CBF8F8l;
     0xCCFF9999l;
     0x95EA1414l;
     0x03ED5858l;
     0x56F7DCDCl;
     0xD4E18B8Bl;
     0x1C1B1515l;
     0x1EADA2A2l;
     0xD70CD3D3l;
     0xFB2BE2E2l;
     0xC31DC8C8l;
     0x8E195E5El;
     0xB5C22C2Cl;
     0xE9894949l;
     0xCF12C1C1l;
     0xBF7E9595l;
     0xBA207D7Dl;
     0xEA641111l;
     0x77840B0Bl;
     0x396DC5C5l;
     0xAF6A8989l;
     0x33D17C7Cl;
     0xC9A17171l;
     0x62CEFFFFl;
     0x7137BBBBl;
     0x81FB0F0Fl;
     0x793DB5B5l;
     0x0951E1E1l;
     0xADDC3E3El;
     0x242D3F3Fl;
     0xCDA47676l;
     0xF99D5555l;
     0xD8EE8282l;
     0xE5864040l;
     0xC5AE7878l;
     0xB9CD2525l;
     0x4D049696l;
     0x44557777l;
     0x080A0E0El;
     0x86135050l;
     0xE730F7F7l;
     0xA1D33737l;
     0x1D40FAFAl;
     0xAA346161l;
     0xED8C4E4El;
     0x06B3B0B0l;
     0x706C5454l;
     0xB22A7373l;
     0xD2523B3Bl;
     0x410B9F9Fl;
     0x7B8B0202l;
     0xA088D8D8l;
     0x114FF3F3l;
     0x3167CBCBl;
     0xC2462727l;
     0x27C06767l;
     0x90B4FCFCl;
     0x20283838l;
     0xF67F0404l;
     0x60784848l;
     0xFF2EE5E5l;
     0x96074C4Cl;
     0x5C4B6565l;
     0xB1C72B2Bl;
     0xAB6F8E8El;
     0x9E0D4242l;
     0x9CBBF5F5l;
     0x52F2DBDBl;
     0x1BF34A4Al;
     0x5FA63D3Dl;
     0x9359A4A4l;
     0x0ABCB9B9l;
     0xEF3AF9F9l;
     0x91EF1313l;
     0x85FE0808l;
     0x49019191l;
     0xEE611616l;
     0x2D7CDEDEl;
     0x4FB22121l;
     0x8F42B1B1l;
     0x3BDB7272l;
     0x47B82F2Fl;
     0x8748BFBFl;
     0x6D2CAEAEl;
     0x46E3C0C0l;
     0xD6573C3Cl;
     0x3E859A9Al;
     0x6929A9A9l;
     0x647D4F4Fl;
     0x2A948181l;
     0xCE492E2El;
     0xCB17C6C6l;
     0x2FCA6969l;
     0xFCC3BDBDl;
     0x975CA3A3l;
     0x055EE8E8l;
     0x7AD0EDEDl;
     0xAC87D1D1l;
     0x7F8E0505l;
     0xD5BA6464l;
     0x1AA8A5A5l;
     0x4BB72626l;
     0x0EB9BEBEl;
     0xA7608787l;
     0x5AF8D5D5l;
     0x28223636l;
     0x14111B1Bl;
     0x3FDE7575l;
     0x2979D9D9l;
     0x88AAEEEEl;
     0x3C332D2Dl;
     0x4C5F7979l;
     0x02B6B7B7l;
     0xB896CACAl;
     0xDA583535l;
     0xB09CC4C4l;
     0x17FC4343l;
     0x551A8484l;
     0x1FF64D4Dl;
     0x8A1C5959l;
     0x7D38B2B2l;
     0x57AC3333l;
     0xC718CFCFl;
     0x8DF40606l;
     0x74695353l;
     0xB7749B9Bl;
     0xC4F59797l;
     0x9F56ADADl;
     0x72DAE3E3l;
     0x7ED5EAEAl;
     0x154AF4F4l;
     0x229E8F8Fl;
     0x12A2ABABl;
     0x584E6262l;
     0x07E85F5Fl;
     0x99E51D1Dl;
     0x34392323l;
     0x6EC1F6F6l;
     0x50446C6Cl;
     0xDE5D3232l;
     0x68724646l;
     0x6526A0A0l;
     0xBC93CDCDl;
     0xDB03DADAl;
     0xF8C6BABAl;
     0xC8FA9E9El;
     0xA882D6D6l;
     0x2BCF6E6El;
     0x40507070l;
     0xDCEB8585l;
     0xFE750A0Al;
     0x328A9393l;
     0xA48DDFDFl;
     0xCA4C2929l;
     0x10141C1Cl;
     0x2173D7D7l;
     0xF0CCB4B4l;
     0xD309D4D4l;
     0x5D108A8Al;
     0x0FE25151l;
     0x00000000l;
     0x6F9A1919l;
     0x9DE01A1Al;
     0x368F9494l;
     0x42E6C7C7l;
     0x4AECC9C9l;
     0x5EFDD2D2l;
     0xC1AB7F7Fl;
     0xE0D8A8A8l
  |]

let m2 =
  [| 0xBC75BC32l;
     0xECF3EC21l;
     0x20C62043l;
     0xB3F4B3C9l;
     0xDADBDA03l;
     0x027B028Bl;
     0xE2FBE22Bl;
     0x9EC89EFAl;
     0xC94AC9ECl;
     0xD4D3D409l;
     0x18E6186Bl;
     0x1E6B1E9Fl;
     0x9845980El;
     0xB27DB238l;
     0xA6E8A6D2l;
     0x264B26B7l;
     0x3CD63C57l;
     0x9332938Al;
     0x82D882EEl;
     0x52FD5298l;
     0x7B377BD4l;
     0xBB71BB37l;
     0x5BF15B97l;
     0x47E14783l;
     0x2430243Cl;
     0x510F51E2l;
     0xBAF8BAC6l;
     0x4A1B4AF3l;
     0xBF87BF48l;
     0x0DFA0D70l;
     0xB006B0B3l;
     0x753F75DEl;
     0xD25ED2FDl;
     0x7DBA7D20l;
     0x66AE6631l;
     0x3A5B3AA3l;
     0x598A591Cl;
     0x00000000l;
     0xCDBCCD93l;
     0x1A9D1AE0l;
     0xAE6DAE2Cl;
     0x7FC17FABl;
     0x2BB12BC7l;
     0xBE0EBEB9l;
     0xE080E0A0l;
     0x8A5D8A10l;
     0x3BD23B52l;
     0x64D564BAl;
     0xD8A0D888l;
     0xE784E7A5l;
     0x5F075FE8l;
     0x1B141B11l;
     0x2CB52CC2l;
     0xFC90FCB4l;
     0x312C3127l;
     0x80A38065l;
     0x73B2732Al;
     0x0C730C81l;
     0x794C795Fl;
     0x6B546B41l;
     0x4B924B02l;
     0x53745369l;
     0x9436948Fl;
     0x8351831Fl;
     0x2A382A36l;
     0xC4B0C49Cl;
     0x22BD22C8l;
     0xD55AD5F8l;
     0xBDFCBDC3l;
     0x48604878l;
     0xFF62FFCEl;
     0x4C964C07l;
     0x416C4177l;
     0xC742C7E6l;
     0xEBF7EB24l;
     0x1C101C14l;
     0x5D7C5D63l;
     0x36283622l;
     0x672767C0l;
     0xE98CE9AFl;
     0x441344F9l;
     0x149514EAl;
     0xF59CF5BBl;
     0xCFC7CF18l;
     0x3F243F2Dl;
     0xC046C0E3l;
     0x723B72DBl;
     0x5470546Cl;
     0x29CA294Cl;
     0xF0E3F035l;
     0x088508FEl;
     0xC6CBC617l;
     0xF311F34Fl;
     0x8CD08CE4l;
     0xA493A459l;
     0xCAB8CA96l;
     0x68A6683Bl;
     0xB883B84Dl;
     0x38203828l;
     0xE5FFE52El;
     0xAD9FAD56l;
     0x0B770B84l;
     0xC8C3C81Dl;
     0x99CC99FFl;
     0x580358EDl;
     0x196F199Al;
     0x0E080E0Al;
     0x95BF957El;
     0x70407050l;
     0xF7E7F730l;
     0x6E2B6ECFl;
     0x1FE21F6El;
     0xB579B53Dl;
     0x090C090Fl;
     0x61AA6134l;
     0x57825716l;
     0x9F419F0Bl;
     0x9D3A9D80l;
     0x11EA1164l;
     0x25B925CDl;
     0xAFE4AFDDl;
     0x459A4508l;
     0xDFA4DF8Dl;
     0xA397A35Cl;
     0xEA7EEAD5l;
     0x35DA3558l;
     0xED7AEDD0l;
     0x431743FCl;
     0xF866F8CBl;
     0xFB94FBB1l;
     0x37A137D3l;
     0xFA1DFA40l;
     0xC23DC268l;
     0xB4F0B4CCl;
     0x32DE325Dl;
     0x9CB39C71l;
     0x560B56E7l;
     0xE372E3DAl;
     0x87A78760l;
     0x151C151Bl;
     0xF9EFF93Al;
     0x63D163BFl;
     0x345334A9l;
     0x9A3E9A85l;
     0xB18FB142l;
     0x7C337CD1l;
     0x8826889Bl;
     0x3D5F3DA6l;
     0xA1ECA1D7l;
     0xE476E4DFl;
     0x812A8194l;
     0x91499101l;
     0x0F810FFBl;
     0xEE88EEAAl;
     0x16EE1661l;
     0xD721D773l;
     0x97C497F5l;
     0xA51AA5A8l;
     0xFEEBFE3Fl;
     0x6DD96DB5l;
     0x78C578AEl;
     0xC539C56Dl;
     0x1D991DE5l;
     0x76CD76A4l;
     0x3EAD3EDCl;
     0xCB31CB67l;
     0xB68BB647l;
     0xEF01EF5Bl;
     0x1218121El;
     0x602360C5l;
     0x6ADD6AB0l;
     0x4D1F4DF6l;
     0xCE4ECEE9l;
     0xDE2DDE7Cl;
     0x55F9559Dl;
     0x7E487E5Al;
     0x214F21B2l;
     0x03F2037Al;
     0xA065A026l;
     0x5E8E5E19l;
     0x5A785A66l;
     0x655C654Bl;
     0x6258624El;
     0xFD19FD45l;
     0x068D06F4l;
     0x40E54086l;
     0xF298F2BEl;
     0x335733ACl;
     0x17671790l;
     0x057F058El;
     0xE805E85El;
     0x4F644F7Dl;
     0x89AF896Al;
     0x10631095l;
     0x74B6742Fl;
     0x0AFE0A75l;
     0x5CF55C92l;
     0x9BB79B74l;
     0x2D3C2D33l;
     0x30A530D6l;
     0x2ECE2E49l;
     0x49E94989l;
     0x46684672l;
     0x77447755l;
     0xA8E0A8D8l;
     0x964D9604l;
     0x284328BDl;
     0xA969A929l;
     0xD929D979l;
     0x862E8691l;
     0xD1ACD187l;
     0xF415F44Al;
     0x8D598D15l;
     0xD6A8D682l;
     0xB90AB9BCl;
     0x429E420Dl;
     0xF66EF6C1l;
     0x2F472FB8l;
     0xDDDFDD06l;
     0x23342339l;
     0xCC35CC62l;
     0xF16AF1C4l;
     0xC1CFC112l;
     0x85DC85EBl;
     0x8F228F9El;
     0x71C971A1l;
     0x90C090F0l;
     0xAA9BAA53l;
     0x018901F1l;
     0x8BD48BE1l;
     0x4EED4E8Cl;
     0x8EAB8E6Fl;
     0xAB12ABA2l;
     0x6FA26F3El;
     0xE60DE654l;
     0xDB52DBF2l;
     0x92BB927Bl;
     0xB702B7B6l;
     0x692F69CAl;
     0x39A939D9l;
     0xD3D7D30Cl;
     0xA761A723l;
     0xA21EA2ADl;
     0xC3B4C399l;
     0x6C506C44l;
     0x07040705l;
     0x04F6047Fl;
     0x27C22746l;
     0xAC16ACA7l;
     0xD025D076l;
     0x50865013l;
     0xDC56DCF7l;
     0x8455841Al;
     0xE109E151l;
     0x7ABE7A25l;
     0x139113EFl
  |]

let m3 =
  [| 0xD939A9D9l;
     0x90176790l;
     0x719CB371l;
     0xD2A6E8D2l;
     0x05070405l;
     0x9852FD98l;
     0x6580A365l;
     0xDFE476DFl;
     0x08459A08l;
     0x024B9202l;
     0xA0E080A0l;
     0x665A7866l;
     0xDDAFE4DDl;
     0xB06ADDB0l;
     0xBF63D1BFl;
     0x362A3836l;
     0x54E60D54l;
     0x4320C643l;
     0x62CC3562l;
     0xBEF298BEl;
     0x1E12181El;
     0x24EBF724l;
     0xD7A1ECD7l;
     0x77416C77l;
     0xBD2843BDl;
     0x32BC7532l;
     0xD47B37D4l;
     0x9B88269Bl;
     0x700DFA70l;
     0xF94413F9l;
     0xB1FB94B1l;
     0x5A7E485Al;
     0x7A03F27Al;
     0xE48CD0E4l;
     0x47B68B47l;
     0x3C24303Cl;
     0xA5E784A5l;
     0x416B5441l;
     0x06DDDF06l;
     0xC56023C5l;
     0x45FD1945l;
     0xA33A5BA3l;
     0x68C23D68l;
     0x158D5915l;
     0x21ECF321l;
     0x3166AE31l;
     0x3E6FA23El;
     0x16578216l;
     0x95106395l;
     0x5BEF015Bl;
     0x4DB8834Dl;
     0x91862E91l;
     0xB56DD9B5l;
     0x1F83511Fl;
     0x53AA9B53l;
     0x635D7C63l;
     0x3B68A63Bl;
     0x3FFEEB3Fl;
     0xD630A5D6l;
     0x257ABE25l;
     0xA7AC16A7l;
     0x0F090C0Fl;
     0x35F0E335l;
     0x23A76123l;
     0xF090C0F0l;
     0xAFE98CAFl;
     0x809D3A80l;
     0x925CF592l;
     0x810C7381l;
     0x27312C27l;
     0x76D02576l;
     0xE7560BE7l;
     0x7B92BB7Bl;
     0xE9CE4EE9l;
     0xF10189F1l;
     0x9F1E6B9Fl;
     0xA93453A9l;
     0xC4F16AC4l;
     0x99C3B499l;
     0x975BF197l;
     0x8347E183l;
     0x6B18E66Bl;
     0xC822BDC8l;
     0x0E98450El;
     0x6E1FE26El;
     0xC9B3F4C9l;
     0x2F74B62Fl;
     0xCBF866CBl;
     0xFF99CCFFl;
     0xEA1495EAl;
     0xED5803EDl;
     0xF7DC56F7l;
     0xE18BD4E1l;
     0x1B151C1Bl;
     0xADA21EADl;
     0x0CD3D70Cl;
     0x2BE2FB2Bl;
     0x1DC8C31Dl;
     0x195E8E19l;
     0xC22CB5C2l;
     0x8949E989l;
     0x12C1CF12l;
     0x7E95BF7El;
     0x207DBA20l;
     0x6411EA64l;
     0x840B7784l;
     0x6DC5396Dl;
     0x6A89AF6Al;
     0xD17C33D1l;
     0xA171C9A1l;
     0xCEFF62CEl;
     0x37BB7137l;
     0xFB0F81FBl;
     0x3DB5793Dl;
     0x51E10951l;
     0xDC3EADDCl;
     0x2D3F242Dl;
     0xA476CDA4l;
     0x9D55F99Dl;
     0xEE82D8EEl;
     0x8640E586l;
     0xAE78C5AEl;
     0xCD25B9CDl;
     0x04964D04l;
     0x55774455l;
     0x0A0E080Al;
     0x13508613l;
     0x30F7E730l;
     0xD337A1D3l;
     0x40FA1D40l;
     0x3461AA34l;
     0x8C4EED8Cl;
     0xB3B006B3l;
     0x6C54706Cl;
     0x2A73B22Al;
     0x523BD252l;
     0x0B9F410Bl;
     0x8B027B8Bl;
     0x88D8A088l;
     0x4FF3114Fl;
     0x67CB3167l;
     0x4627C246l;
     0xC06727C0l;
     0xB4FC90B4l;
     0x28382028l;
     0x7F04F67Fl;
     0x78486078l;
     0x2EE5FF2El;
     0x074C9607l;
     0x4B655C4Bl;
     0xC72BB1C7l;
     0x6F8EAB6Fl;
     0x0D429E0Dl;
     0xBBF59CBBl;
     0xF2DB52F2l;
     0xF34A1BF3l;
     0xA63D5FA6l;
     0x59A49359l;
     0xBCB90ABCl;
     0x3AF9EF3Al;
     0xEF1391EFl;
     0xFE0885FEl;
     0x01914901l;
     0x6116EE61l;
     0x7CDE2D7Cl;
     0xB2214FB2l;
     0x42B18F42l;
     0xDB723BDBl;
     0xB82F47B8l;
     0x48BF8748l;
     0x2CAE6D2Cl;
     0xE3C046E3l;
     0x573CD657l;
     0x859A3E85l;
     0x29A96929l;
     0x7D4F647Dl;
     0x94812A94l;
     0x492ECE49l;
     0x17C6CB17l;
     0xCA692FCAl;
     0xC3BDFCC3l;
     0x5CA3975Cl;
     0x5EE8055El;
     0xD0ED7AD0l;
     0x87D1AC87l;
     0x8E057F8El;
     0xBA64D5BAl;
     0xA8A51AA8l;
     0xB7264BB7l;
     0xB9BE0EB9l;
     0x6087A760l;
     0xF8D55AF8l;
     0x22362822l;
     0x111B1411l;
     0xDE753FDEl;
     0x79D92979l;
     0xAAEE88AAl;
     0x332D3C33l;
     0x5F794C5Fl;
     0xB6B702B6l;
     0x96CAB896l;
     0x5835DA58l;
     0x9CC4B09Cl;
     0xFC4317FCl;
     0x1A84551Al;
     0xF64D1FF6l;
     0x1C598A1Cl;
     0x38B27D38l;
     0xAC3357ACl;
     0x18CFC718l;
     0xF4068DF4l;
     0x69537469l;
     0x749BB774l;
     0xF597C4F5l;
     0x56AD9F56l;
     0xDAE372DAl;
     0xD5EA7ED5l;
     0x4AF4154Al;
     0x9E8F229El;
     0xA2AB12A2l;
     0x4E62584El;
     0xE85F07E8l;
     0xE51D99E5l;
     0x39233439l;
     0xC1F66EC1l;
     0x446C5044l;
     0x5D32DE5Dl;
     0x72466872l;
     0x26A06526l;
     0x93CDBC93l;
     0x03DADB03l;
     0xC6BAF8C6l;
     0xFA9EC8FAl;
     0x82D6A882l;
     0xCF6E2BCFl;
     0x50704050l;
     0xEB85DCEBl;
     0x750AFE75l;
     0x8A93328Al;
     0x8DDFA48Dl;
     0x4C29CA4Cl;
     0x141C1014l;
     0x73D72173l;
     0xCCB4F0CCl;
     0x09D4D309l;
     0x108A5D10l;
     0xE2510FE2l;
     0x00000000l;
     0x9A196F9Al;
     0xE01A9DE0l;
     0x8F94368Fl;
     0xE6C742E6l;
     0xECC94AECl;
     0xFDD25EFDl;
     0xAB7FC1ABl;
     0xD8A8E0D8l
  |]

let ord c = int_of_char c
let ord32 c = Int32.of_int (ord c)

let unpack_longs s n =
  let slen = String.length s in
  if slen / 4 < n
  then
    failwith
      ("unpack_longs: asked to unpack "
      ^^ string_of_int n
      ^^ " longs from\n    string length "
      ^^ string_of_int slen)
  else (
    let rec unpack_long i accum =
      if i == n
      then List.rev accum
      else (
        let a = ord32 s.[(i * 4) + 0] in
        let b = ord32 s.[(i * 4) + 1] in
        let c = ord32 s.[(i * 4) + 2] in
        let d = ord32 s.[(i * 4) + 3] in
        unpack_long (i + 1) (or32 (d << 24) (or32 (c << 16) (or32 (b << 8) a)) :: accum))
    in
    Array.of_list (unpack_long 0 []))

let chr x = char_of_int x
let chr32 x = chr (Int32.to_int x)

let pack_long b x =
  Buffer.add_char b (chr32 (and32 (x >> 0) 0xFFl));
  Buffer.add_char b (chr32 (and32 (x >> 8) 0xFFl));
  Buffer.add_char b (chr32 (and32 (x >> 16) 0xFFl));
  Buffer.add_char b (chr32 (and32 (x >> 24) 0xFFl))

let pack_longs a =
  let b = Buffer.create 4 in
  for i = 0 to Array.length a - 1 do
    pack_long b a.(i)
  done;
  Buffer.contents b

let string_map f s =
  let string_len = String.length s in
  let rec apply i = if i = string_len then [] else f s.[i] :: apply (i + 1) in
  apply 0

let mds_rem a b =
  let ( << ) x y = Int64.shift_left x y in
  let ( >> ) x y = Int64.shift_right_logical x y in
  let ( ^ ) x y = Int64.logxor x y in
  let ( & ) x y = Int64.logand x y in
  let ( -|- ) x y = Int64.logor x y in
  let ff x = x & 0xFFL in
  let ffi x = Int64.to_int (ff x) in
  let rec mds_rem_ab a b = function
    | 8 -> ffi (b >> 24), ffi (b >> 16), ffi (b >> 8), ffi b
    | i ->
      (* Get most significant coefficient *)
      let t = ff (b >> 24) in
      (* Shift the "others" up *)
      let b = (b << 8) -|- ff (a >> 24) in
      let a = a << 8 in
      let u = t << 1 in
      (* Subtract the modular polynomial on overflow *)
      let u = if int64true (t & 0x80L) then u ^ 0x14dL else u in
      (* Remove t * (a * x^2 + 1) *)
      let b = b ^ t ^ (u << 16) in
      (* Form u = a*t + t/a = t*(a + 1/a) *)
      let u = u ^ (0x7FFFFFFFL & t >> 1) in
      (* Add the modular polynomial on underflow *)
      let u = if int64true (t & 0x01L) then u ^ 0xA6L else u in
      (* Remove t * (a + 1/a) * (x^3 + x) *)
      let b = b ^ ((u << 24) -|- (u << 8)) in
      mds_rem_ab a b (i + 1)
  in
  mds_rem_ab (Int64.of_int32 a & 0xFFFFFFFFL) (Int64.of_int32 b & 0xFFFFFFFFL) 0

let init key =
  let keylength = String.length key in
  if keylength != 32
  then failwith ("init: key length must be 32, got key length " ^^ string_of_int keylength)
  else (
    let le_longs = unpack_longs key 8 in
    let sf, se, sd, sc = mds_rem le_longs.(0) le_longs.(1) in
    let sb, sa, s9, s8 = mds_rem le_longs.(2) le_longs.(3) in
    let s7, s6, s5, s4 = mds_rem le_longs.(4) le_longs.(5) in
    let s3, s2, s1, s0 = mds_rem le_longs.(6) le_longs.(7) in
    let k = Array.of_list (string_map (fun c -> ord c) key) in
    let mds i qa qb qc qd ia ib ic id =
      let xor x y = Int32.to_int (xor32 (Int32.of_int x) (Int32.of_int y)) in
      xor qa.(xor qb.(xor qc.(xor qd.(i) ia) ib) ic) id
    in
    let fix data = Array.of_list (List.rev data) in
    let rec calc_k accum = function
      | 40 -> fix accum
      | i ->
        let j = i + 1 in
        let a =
          xor4_32
            m0.(mds i q0 q0 q1 q1 k.(24) k.(16) k.(8) k.(0))
            m1.(mds i q0 q1 q1 q0 k.(25) k.(17) k.(9) k.(1))
            m2.(mds i q1 q0 q0 q0 k.(26) k.(18) k.(10) k.(2))
            m3.(mds i q1 q1 q0 q1 k.(27) k.(19) k.(11) k.(3))
        in
        let b =
          xor4_32
            m0.(mds j q0 q0 q1 q1 k.(28) k.(20) k.(12) k.(4))
            m1.(mds j q0 q1 q1 q0 k.(29) k.(21) k.(13) k.(5))
            m2.(mds j q1 q0 q0 q0 k.(30) k.(22) k.(14) k.(6))
            m3.(mds j q1 q1 q0 q1 k.(31) k.(23) k.(15) k.(7))
        in
        let b = or32 (b << 8) (and32 (b >> 24) 0xFFl) in
        let a = add32 a b in
        let a' = add32 a b in
        calc_k (or32 (a' << 9) (and32 (a' >> 23) 0x1FFl) :: a :: accum) (i + 2)
    in
    let rec calc_sbox s0list s1list s2list s3list = function
      | 256 -> [| fix s0list; fix s1list; fix s2list; fix s3list |]
      | i ->
        calc_sbox
          (m0.(mds i q0 q0 q1 q1 sc s8 s4 s0) :: s0list)
          (m1.(mds i q0 q1 q1 q0 sd s9 s5 s1) :: s1list)
          (m2.(mds i q1 q0 q0 q0 se sa s6 s2) :: s2list)
          (m3.(mds i q1 q1 q0 q1 sf sb s7 s3) :: s3list)
          (i + 1)
    in
    { k = calc_k [] 0; s = calc_sbox [] [] [] [] 0 })

let encrypt ctx text =
  let words = unpack_longs text 4 in
  let k = ctx.k in
  let r0 = xor32 k.(0) words.(0) in
  let r1 = xor32 k.(1) words.(1) in
  let r2 = xor32 k.(2) words.(2) in
  let r3 = xor32 k.(3) words.(3) in
  let s = ctx.s in
  let s0, s1, s2, s3 = s.(0), s.(1), s.(2), s.(3) in
  let rec round (r0, r1, r2, r3) = function
    | 8 -> r0, r1, r2, r3
    | i ->
      let _i x = Int32.to_int x in
      let t0 =
        xor4_32
          s0.(_i (and32 r0 0xFFl))
          s1.(_i (and32 (r0 >> 8) 0xFFl))
          s2.(_i (and32 (r0 >> 16) 0xFFl))
          s3.(_i (and32 (r0 >> 24) 0xFFl))
      in
      let t1 =
        xor4_32
          s0.(_i (and32 (r1 >> 24) 0xFFl))
          s1.(_i (and32 r1 0xFFl))
          s2.(_i (and32 (r1 >> 8) 0xFFl))
          s3.(_i (and32 (r1 >> 16) 0xFFl))
      in
      let r2 = xor32 r2 (add32 (add32 t0 t1) k.(8 + (4 * i))) in
      let r2 = or32 (and32 (r2 >> 1) 0x7FFFFFFFl) (r2 << 31) in
      let r3 = or32 (and32 (r3 >> 31) 1l) (r3 << 1) in
      let r3 = xor32 r3 (add32 t0 (add32 (t1 << 1) k.(9 + (4 * i)))) in
      let t3 =
        xor4_32
          s0.(_i (and32 r2 0xFFl))
          s1.(_i (and32 (r2 >> 8) 0xFFl))
          s2.(_i (and32 (r2 >> 16) 0xFFl))
          s3.(_i (and32 (r2 >> 24) 0xFFl))
      in
      let t4 =
        xor4_32
          s0.(_i (and32 (r3 >> 24) 0xFFl))
          s1.(_i (and32 r3 0xFFl))
          s2.(_i (and32 (r3 >> 8) 0xFFl))
          s3.(_i (and32 (r3 >> 16) 0xFFl))
      in
      let r0 = xor32 r0 (add32 t3 (add32 t4 k.(10 + (4 * i)))) in
      let r0 = or32 (and32 (r0 >> 1) 0x7FFFFFFFl) (r0 << 31) in
      let r1 = or32 (and32 (r1 >> 31) 1l) (r1 << 1) in
      let r1 = xor32 r1 (add32 t3 (add32 (t4 << 1) k.(11 + (4 * i)))) in
      round (r0, r1, r2, r3) (i + 1)
  in
  let r0, r1, r2, r3 = round (r0, r1, r2, r3) 0 in
  pack_longs [| xor32 k.(4) r2; xor32 k.(5) r3; xor32 k.(6) r0; xor32 k.(7) r1 |]

let decrypt ctx text =
  let words = unpack_longs text 4 in
  let k = ctx.k in
  let r0 = xor32 k.(4) words.(0) in
  let r1 = xor32 k.(5) words.(1) in
  let r2 = xor32 k.(6) words.(2) in
  let r3 = xor32 k.(7) words.(3) in
  let s = ctx.s in
  let s0, s1, s2, s3 = s.(0), s.(1), s.(2), s.(3) in
  let rec round (r0, r1, r2, r3) = function
    | -1 -> r0, r1, r2, r3
    | i ->
      let _i x = Int32.to_int x in
      let t0 =
        xor4_32
          s0.(_i (and32 r0 0xFFl))
          s1.(_i (and32 (r0 >> 8) 0xFFl))
          s2.(_i (and32 (r0 >> 16) 0xFFl))
          s3.(_i (and32 (r0 >> 24) 0xFFl))
      in
      let t1 =
        xor4_32
          s0.(_i (and32 (r1 >> 24) 0xFFl))
          s1.(_i (and32 r1 0xFFl))
          s2.(_i (and32 (r1 >> 8) 0xFFl))
          s3.(_i (and32 (r1 >> 16) 0xFFl))
      in
      let r2 = or32 (and32 (r2 >> 31) 0x1Fl) (r2 << 1) in
      let r2 = xor32 r2 (add32 t0 (add32 t1 k.(10 + (4 * i)))) in
      let r3 = xor32 r3 (add32 (add32 t0 (t1 << 1)) k.(11 + (4 * i))) in
      let r3 = or32 (and32 (r3 >> 1) 0x7FFFFFFFl) (r3 << 31) in
      let t3 =
        xor4_32
          s0.(_i (and32 r2 0xFFl))
          s1.(_i (and32 (r2 >> 8) 0xFFl))
          s2.(_i (and32 (r2 >> 16) 0xFFl))
          s3.(_i (and32 (r2 >> 24) 0xFFl))
      in
      let t4 =
        xor4_32
          s0.(_i (and32 (r3 >> 24) 0xFFl))
          s1.(_i (and32 r3 0xFFl))
          s2.(_i (and32 (r3 >> 8) 0xFFl))
          s3.(_i (and32 (r3 >> 16) 0xFFl))
      in
      let r0 = or32 (and32 (r0 >> 31) 0x1Fl) (r0 << 1) in
      let r0 = xor32 r0 (add32 t3 (add32 t4 k.(8 + (4 * i)))) in
      let r1 = xor32 r1 (add32 (add32 t3 (t4 << 1)) k.(9 + (4 * i))) in
      let r1 = or32 (and32 (r1 >> 1) 0x7FFFFFFFl) (r1 << 31) in
      round (r0, r1, r2, r3) (i - 1)
  in
  let r0, r1, r2, r3 = round (r0, r1, r2, r3) 7 in
  pack_longs [| xor32 k.(0) r2; xor32 k.(1) r3; xor32 k.(2) r0; xor32 k.(3) r1 |]

(*
let test() =
  let results = List.map (fun (k,p,c) ->
              let x1 = init k in
              let c' = encrypt x1 p in
              let x2 = init k in
              let p' = decrypt x2 c in
                (p = p') && (c = c'))
    [("\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x37\x52\x7B\xE0\x05\x23\x34\xB8\x9F\x0C\xFC\xCA\xE8\x7C\xFA\x20");
     ("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F");
     ("\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
      "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D",
      "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6");
     ("\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6",
      "\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7",
      "\xC5\xA3\xE7\xCE\xE0\xF1\xB7\x26\x05\x28\xA6\x8F\xB4\xEA\x05\xF2");
     ("\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66",
      "\xC5\xA3\xE7\xCE\xE0\xF1\xB7\x26\x05\x28\xA6\x8F\xB4\xEA\x05\xF2",
      "\x43\xD5\xCE\xC3\x27\xB2\x4A\xB9\x0A\xD3\x4A\x79\xD0\x46\x91\x51");
     ("\x2E\x21\x58\xBC\x3E\x5F\xC7\x14\xC1\xEE\xEC\xA0\xEA\x69\x6D\x48\xD2\xDE\xD7\x3E\x59\x31\x9A\x81\x38\xE0\x33\x1F\x0E\xA1\x49\xEA",
      "\x24\x8A\x7F\x35\x28\xB1\x68\xAC\xFD\xD1\x38\x6E\x3F\x51\xE3\x0C",
      "\x43\x10\x58\xF4\xDB\xC7\xF7\x34\xDA\x4F\x02\xF0\x4C\xC4\xF4\x59");
     ("\x24\x8A\x7F\x35\x28\xB1\x68\xAC\xFD\xD1\x38\x6E\x3F\x51\xE3\x0C\x2E\x21\x58\xBC\x3E\x5F\xC7\x14\xC1\xEE\xEC\xA0\xEA\x69\x6D\x48",
      "\x43\x10\x58\xF4\xDB\xC7\xF7\x34\xDA\x4F\x02\xF0\x4C\xC4\xF4\x59",
      "\x37\xFE\x26\xFF\x1C\xF6\x61\x75\xF5\xDD\xF4\xC3\x3B\x97\xA2\x05");
    ]
  in
    match List.fold_right (fun a b -> a && b) results true with
    | true -> Printf.printf "all tests passed!\n"
    | false -> failwith "not all tests passed"

let () = test ()

*)
