OCC = ocamlopt
EXT = cmx
UNIX = unix.$(EXT)

owps: clean
	$(OCC) -c bin.mli bin.ml
	$(OCC) -c sha256.ml
	$(OCC) -c bin.ml
	$(OCC) -c prompt.mli prompt.ml
	$(OCC) -c cbc.mli cbc.ml
	$(OCC) -c twofish.ml pws.ml
	$(OCC) -o opws $(UNIX) bin.$(EXT) twofish.$(EXT) cbc.$(EXT) prompt.$(EXT) sha256.$(EXT) pws.$(EXT)

clean:
	rm -f *.cmx *.cmo *.cmi opws

