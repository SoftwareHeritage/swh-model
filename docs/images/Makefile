
MERKLE_DAG =  swh-merkle-dag.pdf swh-merkle-dag.svg

BUILD_TARGETS =
BUILD_TARGETS += $(MERKLE_DAG)

all: $(BUILD_TARGETS)


%.svg: %.dia
	inkscape -l $@ $<

%.pdf: %.dia
	inkscape -A $@ $<

clean:
	-rm -f $(BUILD_TARGETS)
