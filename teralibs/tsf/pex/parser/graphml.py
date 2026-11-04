import dataclasses
import xml.sax
import xml.sax.handler
from typing import Any

from teralibs.tsf.utils.exception import ParserError


class InvalidAttributeError(ParserError):
    """Raised when an XML attribute is missing, duplicated, or misconfigured."""

    def __init__(self, element, attribute, details=None, missing=True):
        """Initializes the exception with descriptive structural context."""
        self.element = element
        self.attribute = attribute
        self.missing = missing
        message = f"Element '{element}' contains an invalid attribute: '{attribute}'"
        if details:
            message += f" ({details})"
        super().__init__(message)


def convert_attribute(attr_type, value):
    """Convert a GraphML string value to its native Python type.

    Integers accept hex/binary prefixes to match Ruby's Integer() method.
    """
    if attr_type == "boolean":
        val_strip = value.strip()
        return bool(val_strip) and val_strip.lower() != "false"

    if attr_type in ("int", "long"):
        return int(value.strip(), 0)

    if attr_type in ("float", "double"):
        return float(value)

    if attr_type == "string":
        return value

    raise ValueError(f"Unsupported attribute type: {attr_type}")


@dataclasses.dataclass
class MetaAttribute:
    """Defines global validation rules and schemas for graph data attributes."""

    id: str
    name: str
    type: str
    domain: str = "all"
    default: Any = None

    @classmethod
    def from_key(cls, key_element):
        """Generates a MetaAttribute instance directly from a parsed Key object."""
        default_val = key_element.default.value if key_element.default else None
        return cls(
            key_element.id,
            key_element.attr_name,
            key_element.attr_type,
            domain=key_element.domain,
            default=default_val,
        )

    def convert(self, value):
        """Normalizes and typecasts incoming data elements."""
        return convert_attribute(self.type, value)

    def valid_for(self, element):
        """Determines if the attribute domain matches the specific target component type."""
        if self.domain == "all":
            return True
        return self.domain == getattr(element, "ELEMENT_NAME", None)


class AttributeContainer:
    """Base structural class allowing an entity to retain parsed properties."""

    def __init__(self):
        """Initializes internal attribute dict storage."""
        self.attributes = {}

    def __getitem__(self, key):
        """Allows accessing attributes using container[key] syntax."""
        return self.attributes[key]

    def __setitem__(self, key, value):
        """Allows setting attributes using container[key] = value syntax."""
        self.attributes[key] = value


class Data:
    """Represents an active data assignment token mapping onto parent containers."""

    ELEMENT_NAME = "data"

    def __init__(self, key):
        """Tracks the explicit lookup key constraint reference."""
        self.key = key
        self.value = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Validates entry specifications and constructs data parameters."""
        key = xml_attrs.get("key")
        if key is None:
            raise InvalidAttributeError("data", "key")
        return cls(key)

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class Default:
    """Tracks generic fallback parameter defaults within a specification key block."""

    ELEMENT_NAME = "default"

    def __init__(self, value=None):
        """Initializes the inner fallback values."""
        self.value = value

    @classmethod
    def from_xml_attributes(cls, _xml_attrs):
        """Constructs an empty property default wrapper."""
        return cls()

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class Edge(AttributeContainer):
    """Tracks directional or non-directional block dependencies inside graphs."""

    ELEMENT_NAME = "edge"

    def __init__(self, source, target, directed, id_=None):
        """Maps relationship constraints onto execution nodes."""
        super().__init__()
        self.source = source
        self.target = target
        self.directed = directed
        self.id = id_

    @classmethod
    def from_xml_attributes(cls, xml_attrs, edgedefault):
        """Calculates direction properties using parent context defaults."""
        source = xml_attrs.get("source")
        if source is None:
            raise InvalidAttributeError("edge", "source")

        target = xml_attrs.get("target")
        if target is None:
            raise InvalidAttributeError("edge", "target")

        directed_attr = xml_attrs.get("directed")
        if directed_attr is None:
            directed = edgedefault == "directed"
        elif directed_attr in ("true", "false"):
            directed = directed_attr == "true"
        else:
            raise InvalidAttributeError(
                "edge",
                "directed",
                details="must be either true or false when specified",
                missing=False,
            )

        return cls(source, target, directed, id_=xml_attrs.get("id"))

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class Graph(AttributeContainer):
    """Container managing individual nodes and associated flow edges."""

    ELEMENT_NAME = "graph"

    def __init__(self, edgedefault, id_=None):
        """Initializes node tracking tables and default direction metrics."""
        super().__init__()
        self.edgedefault = edgedefault
        self.id = id_
        self.nodes = {}
        self.edges = []

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Extracts configuration maps to set graph environment expectations."""
        edgedefault = xml_attrs.get("edgedefault")
        if edgedefault not in ("directed", "undirected"):
            raise InvalidAttributeError("graph", "edgedefault", missing=edgedefault is None)
        return cls(edgedefault, id_=xml_attrs.get("id"))

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class GraphML:
    """Top level document root container matching complete parsed targets."""

    ELEMENT_NAME = "graphml"

    def __init__(self):
        """Tracks globally gathered elements cross-referenced across parsers."""
        self.nodes = {}
        self.edges = []
        self.graphs = []

    # API
    def __getitem__(self, key):
        """
        Allows access to internal registries using string keys ('nodes', 'edges', 'graphs').

        >>> doc = GraphML()
        >>> print(doc["nodes"])  # Returns the self.nodes dict
        >>> print(doc["edges"])  # Returns the self.edges list
        """
        registries = {"nodes": self.nodes, "edges": self.edges, "graphs": self.graphs}
        if key in registries:
            return registries[key]

        raise KeyError(f"Registry {key!r} not found. Choose from 'nodes', 'edges', or 'graphs'.")

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class Key:
    """Defines structural field layouts valid anywhere within the graph map."""

    ELEMENT_NAME = "key"

    def __init__(self, id_, name, type_, domain):
        """Tracks the validation constraint boundaries."""
        self.id = id_
        self.attr_name = name
        self.attr_type = type_
        self.domain = domain
        self.default = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Enforces schema configuration limits on incoming configuration keys."""
        id_ = xml_attrs.get("id")
        if id_ is None:
            raise InvalidAttributeError("key", "id")

        name = xml_attrs.get("attr.name")
        if name is None:
            raise InvalidAttributeError("key", "attr.name")

        type_ = xml_attrs.get("attr.type")
        if type_ not in ("boolean", "int", "long", "float", "double", "string"):
            raise InvalidAttributeError(
                "key",
                "attr.type",
                details="must be boolean int long float double or string",
                missing=type_ is None,
            )

        domain = xml_attrs.get("for")
        if domain not in ("graph", "node", "edge", "all"):
            raise InvalidAttributeError(
                "key",
                "for",
                details="must be graph node edge or all",
                missing=domain is None,
            )

        return cls(id_, name, type_, domain)

    def set_default(self, default_element):
        """Sets data defaults cleanly, running active parsing conversions."""
        self.default = default_element
        if self.default and self.default.value is not None:
            self.default.value = convert_attribute(self.attr_type, self.default.value)

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class Node(AttributeContainer):
    """Tracks basic blocks containing metadata instructions and subgraphs."""

    ELEMENT_NAME = "node"

    def __init__(self, id_):
        """Establishes tracking fields for relational data flows."""
        super().__init__()
        self.id = id_
        self.edges = []
        self.subgraph = None

    @classmethod
    def from_xml_attributes(cls, xml_attrs):
        """Validates layout properties to confirm structural integrity."""
        id_ = xml_attrs.get("id")
        if id_ is None:
            raise InvalidAttributeError("node", "id")
        return cls(id_)

    def source_edges(self):
        """Inbound dependencies where this node functions as the destination."""
        return [edge for edge in self.edges if edge.target == self.id or not edge.directed]

    def target_edges(self):
        """Outbound branches directing executions further down the chain."""
        return [edge for edge in self.edges if edge.source == self.id or not edge.directed]

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(element={self.ELEMENT_NAME!r})"


class DocumentHandler(xml.sax.handler.ContentHandler):
    """SAX event-handler cleanly re-assembling structured graph environments."""

    def __init__(self):
        """Prepares tracking stacks, registries, and element dispatch tables."""
        super().__init__()
        self.stack = []
        self.nodes = {}
        self.meta_attributes = {}
        self.graphml = None
        self._current_text = []
        self._start_handlers = {
            "data": self._start_data,
            "default": self._start_default,
            "edge": self._start_edge,
            "graph": self._start_graph,
            "graphml": self._start_graphml,
            "key": self._start_key,
            "node": self._start_node,
        }
        self._end_handlers = {
            "default": self._end_default,
            "edge": self._end_edge,
            "graph": self._end_graph,
            "key": self._end_key,
            "node": self._end_node,
        }

    def startElement(self, name, attrs):
        """Intercepts opening tags, validating structural parenting limits."""
        self._current_text = []
        starter = self._start_handlers.get(name)
        if starter is None:
            raise ParserError(f"Unknown element: {name}")
        self.stack.append(starter(dict(attrs.items())))

    def characters(self, content):
        """Buffers ongoing character fragments tracking inline string text."""
        self._current_text.append(content)

    def endElement(self, name):
        """Validates attributes and properties once an XML tag block closes."""
        element = self.stack.pop()
        text_content = "".join(self._current_text)

        if isinstance(element, Data):
            self._store_data(element, text_content)
        elif isinstance(element, Default):
            element.value = text_content

        if isinstance(element, AttributeContainer):
            self._populate_element_default_attributes(element)

        ender = self._end_handlers.get(name)
        if ender is not None:
            ender(element)

    def _require_parent(self, child, parent_types, description):
        """Raises unless the current stack top is an allowed parent type."""
        if not self.stack or not isinstance(self.stack[-1], parent_types):
            raise ParserError(f"The '{child}' element must be a direct child of {description}")

    def _start_data(self, attrs):
        """Opens a data element under an attribute container."""
        self._require_parent("data", AttributeContainer, "an attribute container")
        return Data.from_xml_attributes(attrs)

    def _start_default(self, attrs):
        """Opens a default element under a key."""
        self._require_parent("default", Key, "a 'key' element")
        return Default.from_xml_attributes(attrs)

    def _start_edge(self, attrs):
        """Opens an edge element under a graph and registers it globally."""
        self._require_parent("edge", Graph, "a 'graph' element")

        element = Edge.from_xml_attributes(attrs, self.stack[-1].edgedefault)
        if self.graphml:
            self.graphml.edges.append(element)

        return element

    def _start_graph(self, attrs):
        """Opens a graph element, linking it to a parent node if nested."""
        element = Graph.from_xml_attributes(attrs)
        if self.stack:
            node_stack = isinstance(self.stack[-1], Node)
            if node_stack:
                self.stack[-1].subgraph = element

        if self.graphml:
            self.graphml.graphs.append(element)

        return element

    def _start_graphml(self, _attrs):
        """Opens the top-level graphml root element."""
        if self.stack:
            raise ParserError("The 'graphml' element must be a top-level element")
        self.graphml = GraphML()
        return self.graphml

    def _start_key(self, attrs):
        """Opens a key element, rejecting duplicate ids and attribute names."""
        self._require_parent("key", GraphML, "a 'graphml' element")
        element = Key.from_xml_attributes(attrs)
        if element.id in self.meta_attributes:
            raise InvalidAttributeError("key", "id", details="duplicate key id", missing=False)
        if any(attr.name == element.attr_name for attr in self.meta_attributes.values()):
            raise InvalidAttributeError(
                "key",
                "attr.name",
                details="duplicate key attr.name",
                missing=False,
            )
        return element

    def _start_node(self, attrs):
        """Opens a node element, rejecting duplicate ids and registering it globally."""
        self._require_parent("node", Graph, "a 'graph' element")
        element = Node.from_xml_attributes(attrs)
        if element.id in self.nodes:
            raise InvalidAttributeError("node", "id", details="duplicate node id", missing=False)

        self.nodes[element.id] = element
        if self.graphml:
            self.graphml.nodes[element.id] = element

        return element

    def _store_data(self, element, text_content):
        """Validates a closed data element and writes it onto its parent."""
        parent = self.stack[-1]
        meta_attribute = self.meta_attributes.get(element.key)
        if not meta_attribute or not meta_attribute.valid_for(parent):
            name_str = meta_attribute.name if meta_attribute else element.key
            elem_name = getattr(parent, "ELEMENT_NAME", "unknown")
            raise ParserError(f"The {name_str} attribute is invalid for {elem_name} elements")

        converted_val = meta_attribute.convert(text_content)
        if meta_attribute.type == "string" and parent.attributes.get(meta_attribute.name) is not None:
            parent.attributes[meta_attribute.name] += converted_val
        else:
            parent.attributes[meta_attribute.name] = converted_val

    def _end_default(self, element):
        """Attaches a closed default element to its parent key."""
        self.stack[-1].set_default(element)

    def _end_edge(self, element):
        """Attaches a closed edge element to its parent graph."""
        self.stack[-1].edges.append(element)

    def _end_graph(self, element):
        """Resolves edge endpoints against the graph's nodes once it closes."""
        for edge in element.edges:
            source_node = element.nodes.get(edge.source)
            if source_node is None:
                raise InvalidAttributeError(
                    "edge",
                    "source",
                    details=f"undefined source: '{edge.source}'",
                    missing=False,
                )
            target_node = element.nodes.get(edge.target)
            if target_node is None:
                raise InvalidAttributeError(
                    "edge",
                    "target",
                    details=f"undefined target: '{edge.target}'",
                    missing=False,
                )
            source_node.edges.append(edge)
            target_node.edges.append(edge)

    def _end_key(self, element):
        """Registers a closed key element as a meta attribute."""
        meta_attr = MetaAttribute.from_key(element)
        self.meta_attributes[meta_attr.id] = meta_attr

    def _end_node(self, element):
        """Attaches a closed node element to its parent graph."""
        self.stack[-1].nodes[element.id] = element

    def _populate_element_default_attributes(self, element):
        """Applies configured global schema fallback defaults onto containers."""
        for meta_attribute in self.meta_attributes.values():
            if not meta_attribute.valid_for(element):
                continue
            if meta_attribute.name in element.attributes:
                continue
            if meta_attribute.default is None:
                continue
            element.attributes[meta_attribute.name] = meta_attribute.default


def from_file(file_path):
    """Loads a target GraphML document from the filesystem."""
    parser = xml.sax.make_parser()
    handler = DocumentHandler()

    parser.setContentHandler(handler)
    with open(file_path, "rb") as xml_file:
        parser.parse(xml_file)

    return handler.graphml
