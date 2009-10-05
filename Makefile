OCC = ocamlopt
EXT = cmx
UNIX = unix.cmxa

owps: clean
	$(OCC) -c bin.mli bin.ml
	$(OCC) -c sha256.ml
	$(OCC) -c bin.ml
	$(OCC) -c prompt.mli prompt.ml
	$(OCC) -c cbc.mli cbc.ml
	$(OCC) -c twofish.ml opws.ml
	$(OCC) -o opws $(UNIX) bin.$(EXT) twofish.$(EXT) cbc.$(EXT) prompt.$(EXT) sha256.$(EXT) opws.$(EXT)

clean:
	rm -f *.cmx *.cmo *.cmi *.o opws

