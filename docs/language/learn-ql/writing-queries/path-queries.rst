Creating path queries
#####################

You can create path queries to visualize the flow of information through a codebase.

Overview
========

Security researchers are particularly interested in the way that information flows in a program. Many vulnerabilities are caused by seemingly benign data flowing to unexpected locations, and being used in a malicious way. 
Path queries written with CodeQL are particularly useful for analyzing data flow as they can be used to track the path taken by a variable from its possible starting points (``source``) to its possible end points (``sink``).
To model paths, your query must provide information about the ``source`` and the ``sink``, as well as the data flow steps that link them.

This topic provides information on how to structure a path query file so you can explore the paths associated with the results of data flow analysis. 

.. pull-quote::

    Note

    The alerts generated by path queries are displayed by default in `LGTM <https://lgtm.com>`__ and included in the results generated using the `CodeQL CLI <https://help.semmle.com/codeql/codeql-cli.html>`__. You can also view the path explanations generated by your path query `directly in LGTM <https://lgtm.com/help/lgtm/exploring-data-flow-paths>`__ or in the CodeQL `extension for VS Code <https://help.semmle.com/codeql/codeql-for-vscode.html>`__.


To learn more about modeling data flow with CodeQL, see :doc:`Introduction to data flow <../intro-to-data-flow>`.
For more language-specific information on analyzing data flow, see:

- :doc:`Analyzing data flow in C/C++ <../cpp/dataflow>`
- :doc:`Analyzing data flow in C# <../csharp/dataflow>`
- :doc:`Analyzing data flow in Java <../java/dataflow>` 
- :doc:`Analyzing data flow in JavaScript/TypeScript <../javascript/dataflow>`
- :doc:`Analyzing data flow and tracking tainted data in Python <../python/taint-tracking>`

Path query examples
*******************

The easiest way to get started writing your own path query is to modify one of the existing queries. Visit the links below to see all the built-in path queries:

- `C/C++ path queries <https://help.semmle.com/wiki/label/CCPPOBJ/path-problem>`__
- `C# path queries <https://help.semmle.com/wiki/label/CSHARP/path-problem>`__
- `Java path queries <https://help.semmle.com/wiki/label/java/path-problem>`__
- `JavaScript path queries <https://help.semmle.com/wiki/label/js/path-problem>`__
- `Python path queries <https://help.semmle.com/wiki/label/python/path-problem>`__
 
The Security Lab researchers have used path queries to find security vulnerabilities in various open source projects. To see articles describing how these queries were written, as well as other posts describing other aspects of security research such as exploiting vulnerabilities, see the `GitHub Security Lab website <https://securitylab.github.com/research>`__.

Constructing a path query
=========================

Path queries require certain metadata, query predicates, and ``select`` statement structures. 
Many of the built-in path queries included in CodeQL follow a simple structure, which depends on how the language you are analyzing is modeled with CodeQL.

For C/C++, C#, Java, and JavaScript you should use the following template::

    /**
     * ... 
     * @kind path-problem
     * ...
     */

    import <language>
    import DataFlow::PathGraph
    ...

    from Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink
    where config.hasFlowPath(source, sink)
    select sink.getNode(), source, sink, "<message>"

Where:

- ``DataFlow::Pathgraph`` is the path graph module you need to import from the standard CodeQL libraries.
- ``source`` and ``sink`` are nodes on the `path graph <https://en.wikipedia.org/wiki/Path_graph>`__, and ``DataFlow::PathNode`` is their type.
- ``Configuration`` is a class containing the predicates which define how data may flow between the ``source`` and the ``sink``. 

For Python you should use a slightly different template::

    /**
     * ... 
     * @kind path-problem
     * ...
     */

    import python
    import semmle.python.security.Paths
    ...

    from TaintedPathSource source, TaintedPathSink sink
    where source.flowsTo(sink)
    select sink.getNode(), source, sink, "<message>"

Where:

- ``semmle.python.security.Paths`` is the path graph module imported from the standard CodeQL libraries.
- ``source`` and ``sink`` are nodes on the path graph, ``TaintedPathSource source`` and ``TaintedPathSink`` are their respective types. Note, you do not need to declare a configuration class to define the data flow from the ``source`` to the ``sink`` in a Python path query.


The following sections describe the main requirements for a valid path query. 

Path query metadata
*******************

Path query metadata must contain the property ``@kind path-problem``???this ensures that query results are interpreted and displayed correctly.
The other metadata requirements depend on how you intend to run the query. For more information, see `Query metadata <https://help.semmle.com/QL/learn-ql/writing-queries/introduction-to-queries.html#query-metadata>`__.

Generating path explanations
****************************

In order to generate path explanations, your query needs to compute a `path graph <https://en.wikipedia.org/wiki/Path_graph>`__.
To do this you need to define a `query predicate <https://help.semmle.com/QL/ql-handbook/queries.html#query-predicates>`__ called ``edges`` in your query.
This predicate defines the edge relations of the graph you are computing, and it is used to compute the paths related to each result that your query generates. 
You can import a predefined ``edges`` predicate from a path graph module in one of the standard data flow libraries. In addition to the path graph module, the data flow libraries contain the other ``classes``, ``predicates``, and ``modules`` that are commonly used in data flow analysis. The import statement to use depends on the language that you are analyzing.

For C/C++, C#, Java, and JavaScript you would use::

    import DataFlow::PathGraph

This statement imports the ``PathGraph`` module from the data flow library (``DataFlow.qll``), in which ``edges`` is defined. 

For Python, the ``Paths`` module contains the ``edges`` predicate::

    import semmle.python.security.Paths 

You can also import libraries specifically designed to implement data flow analysis in various common frameworks and environments, and many additional libraries are included with CodeQL. To see examples of the different libraries used in data flow analysis, see the links to the built-in queries above or browse the `standard libraries <https://help.semmle.com/QL/ql-libraries.html>`__.

For all languages, you can also optionally define a ``nodes`` query predicate, which specifies the nodes of the path graph that you are interested in. If ``nodes`` is defined, only edges with endpoints defined by these nodes are selected. If ``nodes`` is not defined, you select all possible endpoints of ``edges``.

Defining your own ``edges`` predicate
-------------------------------------

You can also define your own ``edges`` predicate in the body of your query. It should take the following form::

    query predicate edges(PathNode a, PathNode b) {
    /** Logical conditions which hold if `(a,b)` is an edge in the data flow graph */
    }

For more examples of how to define an ``edges`` predicate, visit the `standard CodeQL libraries <https://help.semmle.com/QL/ql-libraries.html>`__ and search for ``edges``.

Declaring sources and sinks
***************************

You must provide information about the ``source`` and ``sink`` in your path query. These are objects that correspond to the nodes of the paths that you are exploring.
The name and the type of the ``source`` and the ``sink`` must be declared in the ``from`` statement of the query, and the types must be compatible with the nodes of the graph computed by the ``edges`` predicate.

If you are querying C/C++, C#, Java, or JavaScript code (and you have used ``import DataFlow::PathGraph`` in your query), the definitions of the ``source`` and ``sink`` are accessed via the ``Configuration`` class in the data flow library. You should declare all three of these objects in the ``from`` statement.
For example::

    from Configuration config, DataFlow::PathNode source, DataFlow::PathNode sink 

The configuration class is accessed by importing the data flow library. This class contains the predicates which define how data flow is treated in the query:

- ``isSource()`` defines where data may flow from.
- ``isSink()`` defines where data may flow to.

For further information on using the configuration class in your analysis see the sections on global data flow in :doc:`Analyzing data flow in C/C++ <../cpp/dataflow>` and :doc:`Analyzing data flow in C# <../csharp/dataflow>`.

You can also create a configuration for different frameworks and environments by extending the ``Configuration`` class.
For further information, see `defining a class <https://help.semmle.com/QL/ql-handbook/types.html#defining-a-class>`__.

If you are querying Python code (and you have used ``import semmle.python.security.Paths`` in your query) you should declare ``TaintedPathSource source, TaintedPathSink sink`` in your ``from`` statement. You do not need to declare a ``Configuration`` class as the definitions of the ``TaintedPathSource`` and ``TaintedPathSink`` contain all of the type information that is required::

    from TaintedPathSource source, TaintedPathSink sink

You can extend your query by adding different sources and sinks by either defining them in the query, or by importing predefined sources and sinks for specific frameworks and libraries. See the `Python path queries <https://help.semmle.com/wiki/label/python/path-problem>`__ for further details. 

Defining flow conditions
************************

The ``where`` clause defines the logical conditions to apply to the variables declared in the ``from`` clause to generate your results. 
This clause can use `aggregations <https://help.semmle.com/QL/ql-handbook/expressions.html#aggregations>`__, `predicates <https://help.semmle.com/QL/ql-handbook/predicates.html>`__, and logical `formulas <https://help.semmle.com/QL/ql-handbook/formulas.html>`_ to limit the variables of interest to a smaller set which meet the defined conditions. 

When writing a path queries, you would typically include a predicate that holds only if data flows from the ``source`` to the ``sink``. 

For C/C++, C#, Java or JavaScript, you would use the ``hasFlowPath`` predicate to define flow from the ``source`` to the ``sink`` for a given ``Configuration``:: 

    where config.hasFlowPath(source, sink)

For Python, you would simply use the ``flowsTo`` predicate to define flow from the ``source`` to the ``sink``:: 

    where source.flowsTo(sink)

Select clause
*************

Select clauses for path queries consist of four 'columns', with the following structure::

    select element, source, sink, string

The ``element`` and ``string`` columns represent the location of the alert and the alert message respectively, as explained in :doc:`Introduction to writing queries <introduction-to-queries>`. The second and third columns, ``source`` and ``sink``, are nodes on the path graph selected by the query. 
Each result generated by your query is displayed at a single location in the same way as an alert query. Additionally, each result also has an associated path, which can be viewed in LGTM or in the CodeQL `extension for VS Code <https://help.semmle.com/codeql/codeql-for-vscode.html>`__.

The ``element`` that you select in the first column depends on the purpose of the query and the type of issue that it is designed to find. This is particularly important for security issues. For example, if you believe the ``source`` value to be globally invalid or malicious it may be best to display the alert at the ``source``. In contrast, you should consider displaying the alert at the ``sink`` if you believe it is the element that requires sanitization.

The alert message defined in the final column in the ``select`` statement can be developed to give more detail about the alert or path found by the query using links and placeholders. For more information, see :doc:`Defining the results of a query <select-statement>`. 

Further reading
***************

- `Exploring data flow with path queries <https://help.semmle.com/codeql/codeql-for-vscode/procedures/exploring-paths.html>`__
- `CodeQL repository <https://github.com/github/codeql>`__
