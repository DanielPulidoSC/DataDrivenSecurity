# CPE

Common Platform Enumeration (CPE) is a standardized method of describing and identifying classes of applications, operating systems, and hardware devices present among an enterprise's computing assets. CPE does not identify unique instantiations of products on systems, CPE identifies abstract classes of products.

The current version of CPE is 2.3 which is defined through a set of specifications in a stack-based model, where capabilities are based on simpler, more narrowly defined elements that are specified lower in the stack. The model is based on Naming consisting on define a logical structure of Well-formed Names (WFN), URI and formated string bindings and the procedures for converting WFNs to and from the bindings. The name matching helps to compare WFN’s between their atributes and names. The applicability language defines a standard structure to form complex logical expressions such as getting the CPE name for a operating system, the CPE name for an application and a reference to a check for a particular value of a certain configuration setting like enabling a network card. These are called applicability statements which use on guidance, compliance, policies, etc.
Last but not least, the CPE dictionary contents names and metadata to classify and identify a single class of IT product. We have an [online search dictionary](https://nvd.nist.gov/products/cpe/search) and its [statistics](https://nvd.nist.gov/products/cpe/statistics).

![CPE_model](/images/cpe_stack.png)

The CPE version 2.3 specifications, including this specification, collectively replace [CPE22].CPE version 2.3 is intended to provide all the capabilities made available by [CPE22] while adding new features suggested by the CPE user community.
The primary differences between CPE Dictionary versions 2.2 and 2.3 include:
1. Updated deprecation logic that includes one-to-many CPE deprecation
2. Updated change history and provenance data requirements
3. Built-in one-to-one mappingbetween CPE version 2.2 and version 2.3 names; the version 2.3 name is embedded in the version 2.2 name so that the instance document will validate against the version 2.2 schema.

Next, we are going to show and describe each item on [dictionary](https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip) and its attributes in the [standardized schema](https://csrc.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd) so we can decide which are the most interesting parameters to get and tidy the data frame.

**cpe-list**: The cpe-list element acts as a top-level container for CPE Name items. Each individual item must be unique. It includes the ListType complex type defines an element that is used to hold a collection of individual items. The required generator section provides information about when the definition file was compiled and under what version.

**generator**: The GeneratorType complex type defines an element that is used to hold information about when a particular document was compiled, what version of the schema was used, what tool compiled the document, and what version of that tool was used.

**reference**: The ReferencesType complex type defines an element used to hold a collection of individual references. Each reference consists of a piece of text (intended to be human-readable) and a URI (intended to be a URL, and point to a real resource) and is used to point to extra descriptive material, for example a supplier's web site or platform documentation.

**cpe-item**: The cpe-item element denotes a single CPE Name. The required name attribute is a URI which must be a unique key and should follow the URI structure outlined in the CPE Specification. The optional title element is used to provide a human-readable title for the platform. To support uses intended for multiple languages, this element supports the ‘xml:lang’ attribute. At most one title element can appear for each language. There are other optional elements as notes or checks.

**notes**: The notes element holds optional descriptive material. Multiple notes elements are allowed, but only one per language should be used. Note that the language associated with the notes element applies to all child note elements. 

**check**: The CheckType complex type is used to define an element to hold information about an individual check. It includes a checking system specification URI, string content, and an optional external file reference. The checking system specification should be the URI for a particular version of OVAL or a related system testing language, and the content will be an identifier of a test written in that language. The external file reference could be used to point to the file in which the content test identifier is defined. 

