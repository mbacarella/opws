OCC = ocamlopt
UNIX = unix.cmx
EXT = cmx

owps: clean
	$(OCC) -c bin.mli bin.ml
	$(OCC) -c sha256.ml
	$(OCC) -c bin.ml
	$(OCC) -c prompt.mli prompt.ml
	$(OCC) -c pws.ml
	$(OCC) -o opws prompt.$(EXT) bin.$(EXT) sha256.$(EXT) pws.$(EXT)

clean:
	rm -f *.cmx *.cmo *.cmi opws

