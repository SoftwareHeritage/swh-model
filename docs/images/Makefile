
MERKLE_DAG =  swh-merkle-dag.pdf swh-merkle-dag.svg

BUILD_TARGETS =
BUILD_TARGETS += $(MERKLE_DAG)

all: $(BUILD_TARGETS)

%.svg: %.dia
	dia -e $@ $<

%.pdf: %.svg
	set -e; if [ $$(inkscape --version 2>/dev/null | grep -Eo '[0-9]+' | head -1) -gt 0 ]; then \
	  inkscape -o $@ $< ; \
	else \
	  inkscape -A $@ $< ; \
	fi

clean:
	-rm -f $(BUILD_TARGETS)
