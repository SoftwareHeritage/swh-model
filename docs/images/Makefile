
MERKLE_DAG = swh-merkle-dag.svg

BUILD_TARGETS =
BUILD_TARGETS += $(MERKLE_DAG)

all: $(BUILD_TARGETS)


# dia exporters

%.eps: %.dia
	dia -t eps --export $@ $<

%.svg: %.dia
	dia -t svg --export $@ $<

# generic converters

%.pdf: %.eps
	epstopdf $<


clean:
	-rm -f $(BUILD_TARGETS)
