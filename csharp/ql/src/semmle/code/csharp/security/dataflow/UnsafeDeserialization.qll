/**
 * Provides a taint-tracking configuration for reasoning about uncontrolled data
 * in calls to unsafe deserializers (XML, JSON, XAML).
 */

import csharp

module UnsafeDeserialization {
  private import semmle.code.csharp.serialization.Deserializers

  /**
   * A data flow source for unsafe deserialization vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for unsafe deserialization vulnerabilities to an instance method.
   */
  abstract class InstanceMethodSink extends DataFlow::Node { }

  /**
   * A data flow sink for unsafe deserialization vulnerabilities to a static method or constructor call.
   */
  abstract class ConstructorOrStaticMethodSink extends DataFlow::Node { }

  /**
   * A sanitizer for unsafe deserialization vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * User input to object method call deserialization flow tracking.
   */
  class TaintToObjectMethodTrackingConfig extends TaintTracking::Configuration {
    TaintToObjectMethodTrackingConfig() { this = "UnsafeDeserialization1" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof InstanceMethodSink }

    override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
  }

  /**
   * User input to static method or constructor call deserialization flow tracking.
   */
  class TaintToConstructorOrStaticMethodTrackingConfig extends TaintTracking::Configuration {
    TaintToConstructorOrStaticMethodTrackingConfig() { this = "UnsafeDeserialization2" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) { sink instanceof ConstructorOrStaticMethodSink }

    override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
  }

  /**
   * User input to instance type flow tracking.
   */
  class TaintToObjectTypeTrackingConfig extends TaintTracking::Configuration {
    TaintToObjectTypeTrackingConfig() { this = "TaintToObjectTypeTrackingConfig" }

    override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc |
        mc.getTarget() instanceof UnsafeDeserializerCallable and
        sink.asExpr() = mc.getQualifier()
      )
    }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
      exists(MethodCall mc, Method m |
        m = mc.getTarget() and
        m.getDeclaringType().hasQualifiedName("System.Type") and
        m.hasName("GetType") and
        m.isStatic() and
        n1.asExpr() = mc.getArgument(0) and
        n2.asExpr() = mc
      )
      or
      exists(ObjectCreation oc |
        n1.asExpr() = oc.getAnArgument() and
        n2.asExpr() = oc and
        oc.getObjectType() instanceof StrongTypeDeserializer
      )
    }
  }

  /**
   * Unsafe deserializer creation to usage tracking config.
   */
  class WeakTypeCreationToUsageTrackingConfig extends TaintTracking::Configuration {
    WeakTypeCreationToUsageTrackingConfig() { this = "DeserializerCreationToUsageTrackingConfig" }

    override predicate isSource(DataFlow::Node source) {
      exists(ObjectCreation oc |
        oc.getObjectType() instanceof WeakTypeDeserializer and
        source.asExpr() = oc
      )
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc |
        mc.getTarget() instanceof UnsafeDeserializerCallable and
        sink.asExpr() = mc.getQualifier()
      )
    }
  }

  /**
   * Safe deserializer creation to usage tracking config.
   */
  abstract class SafeConstructorTrackingConfig extends TaintTracking::Configuration {
    bindingset[this]
    SafeConstructorTrackingConfig() { any() }
  }

  /** BinaryFormatter */
  private predicate isBinaryFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof BinaryFormatterDeserializeMethod and
      not mc.getArgument(0).hasValue()
      or
      m instanceof BinaryFormatterUnsafeDeserializeMethod and
      not mc.getArgument(0).hasValue()
      or
      m instanceof BinaryFormatterUnsafeDeserializeMethodResponseMethod and
      not mc.getArgument(0).hasValue()
    )
  }

  private abstract class BinaryFormatterSink extends InstanceMethodSink { }

  private class BinaryFormatterDeserializeMethodSink extends BinaryFormatterSink {
    BinaryFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isBinaryFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** SoapFormatter */
  private predicate isSoapFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof SoapFormatterDeserializeMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class SoapFormatterSink extends InstanceMethodSink { }

  private class SoapFormatterDeserializeMethodSink extends SoapFormatterSink {
    SoapFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isSoapFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** ObjectStateFormatter */
  private predicate isObjectStateFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof ObjectStateFormatterDeserializeMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class ObjectStateFormatterSink extends InstanceMethodSink { }

  private class ObjectStateFormatterDeserializeMethodSink extends ObjectStateFormatterSink {
    ObjectStateFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isObjectStateFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** NetDataContractSerializer */
  private predicate isNetDataContractSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof NetDataContractSerializerDeserializeMethod and
      not mc.getArgument(0).hasValue()
      or
      m instanceof NetDataContractSerializerReadObjectMethod and
      not mc.getArgument(0).hasValue()
    )
  }

  private abstract class NetDataContractSerializerSink extends InstanceMethodSink { }

  private class NetDataContractSerializerDeserializeMethodSink extends NetDataContractSerializerSink {
    NetDataContractSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isNetDataContractSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** DataContractJsonSerializer */
  private predicate isDataContractJsonSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof DataContractJsonSerializerReadObjectMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class DataContractJsonSerializerSink extends InstanceMethodSink { }

  private class DataContractJsonSerializerDeserializeMethodSink extends DataContractJsonSerializerSink {
    DataContractJsonSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isDataContractJsonSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class DataContractJsonSafeConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    DataContractJsonSafeConstructorTrackingConfiguration() {
      this = "DataContractJsonSafeConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
        DataContractJsonSerializerClass and
      source.asExpr().(ObjectCreation).getTarget().getNumberOfParameters() > 0 and
      source.asExpr().(ObjectCreation).getArgument(0) instanceof TypeofExpr
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isDataContractJsonSerializerCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** JavaScriptSerializer */
  private predicate isJavaScriptSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof JavaScriptSerializerClassDeserializeMethod and
      not mc.getArgument(0).hasValue()
      or
      m instanceof JavaScriptSerializerClassDeserializeObjectMethod and
      not mc.getArgument(0).hasValue()
    )
  }

  private abstract class JavaScriptSerializerSink extends InstanceMethodSink { }

  private class JavaScriptSerializerDeserializeMethodSink extends JavaScriptSerializerSink {
    JavaScriptSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isJavaScriptSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class JavaScriptSerializerSafeConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    JavaScriptSerializerSafeConstructorTrackingConfiguration() {
      this = "JavaScriptSerializerSafeConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
        JavaScriptSerializerClass and
      source.asExpr().(ObjectCreation).getTarget().getNumberOfParameters() = 0
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isJavaScriptSerializerCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** XmlObjectSerializer */
  private predicate isXmlObjectSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof XmlObjectSerializerReadObjectMethod and
    not mc.getArgument(0).hasValue() and
    not mc.targetIsLocalInstance()
  }

  private abstract class XmlObjectSerializerSink extends InstanceMethodSink { }

  private class XmlObjectSerializerDeserializeMethodSink extends XmlObjectSerializerSink {
    XmlObjectSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isXmlObjectSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class XmlObjectSerializerDerivedConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    XmlObjectSerializerDerivedConstructorTrackingConfiguration() {
      this = "XmlObjectSerializerDerivedConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType().getABaseType+() instanceof
        XmlObjectSerializerClass and
      not (
        source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
          DataContractSerializerClass or
        source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
          NetDataContractSerializerClass
      )
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isXmlObjectSerializerCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** XmlSerializer */
  private predicate isXmlSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof XmlSerializerDeserializeMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class XmlSerializerSink extends InstanceMethodSink { }

  private class XmlSerializerDeserializeMethodSink extends XmlSerializerSink {
    XmlSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isXmlSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class XmlSerializerSafeConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    XmlSerializerSafeConstructorTrackingConfiguration() {
      this = "XmlSerializerSafeConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof XmlSerializerClass and
      source.asExpr().(ObjectCreation).getTarget().getNumberOfParameters() > 0 and
      source.asExpr().(ObjectCreation).getArgument(0) instanceof TypeofExpr
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isXmlSerializerCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** DataContractSerializer */
  private predicate isDataContractSerializerCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof DataContractSerializerReadObjectMethod
      or
      m instanceof XmlObjectSerializerReadObjectMethod
    ) and
    not mc.getArgument(0).hasValue()
  }

  private abstract class DataContractSerializerSink extends InstanceMethodSink { }

  private class DataContractSerializerDeserializeMethodSink extends DataContractSerializerSink {
    DataContractSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isDataContractSerializerCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class DataContractSerializerSafeConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    DataContractSerializerSafeConstructorTrackingConfiguration() {
      this = "DataContractSerializerSafeConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
        DataContractSerializerClass and
      source.asExpr().(ObjectCreation).getTarget().getNumberOfParameters() > 0 and
      source.asExpr().(ObjectCreation).getArgument(0) instanceof TypeofExpr
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isDataContractSerializerCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** XmlMessageFormatter */
  private predicate isXmlMessageFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof XmlMessageFormatterReadMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class XmlMessageFormatterSink extends InstanceMethodSink { }

  private class XmlMessageFormatterDeserializeMethodSink extends XmlMessageFormatterSink {
    XmlMessageFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isXmlMessageFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  private class XmlMessageFormatterSafeConstructorTrackingConfiguration extends SafeConstructorTrackingConfig {
    XmlMessageFormatterSafeConstructorTrackingConfiguration() {
      this = "XmlMessageFormatterSafeConstructorTrackingConfiguration"
    }

    override predicate isSource(DataFlow::Node source) {
      source.asExpr().(ObjectCreation).getTarget().getDeclaringType() instanceof
        XmlMessageFormatterClass and
      source.asExpr().(ObjectCreation).getTarget().getNumberOfParameters() > 0 and
      source.asExpr().(ObjectCreation).getArgument(0) instanceof TypeofExpr
    }

    override predicate isSink(DataFlow::Node sink) {
      exists(MethodCall mc, Method m |
        isXmlMessageFormatterCall(mc, m) and
        mc.getQualifier() = sink.asExpr()
      )
    }
  }

  /** LosFormatter */
  private predicate isLosFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof LosFormatterDeserializeMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class LosFormatterSink extends InstanceMethodSink { }

  private class LosFormatterDeserializeMethodSink extends LosFormatterSink {
    LosFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isLosFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** fastJSON */
  private predicate isFastJsonCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof FastJsonClassToObjectMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class FastJsonSink extends ConstructorOrStaticMethodSink { }

  private class FastJsonDeserializeMethodSink extends FastJsonSink {
    FastJsonDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isFastJsonCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** Activity */
  private predicate isActivityCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof ActivityLoadMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class ActivitySink extends InstanceMethodSink { }

  private class ActivityDeserializeMethodSink extends ActivitySink {
    ActivityDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isActivityCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** ResourceReader */
  private predicate isResourceReaderCall(Call mc, Constructor m) {
    m = mc.getTarget() and
    m instanceof ResourceReaderConstructor and
    not mc.getArgument(0).hasValue()
  }

  private abstract class ResourceReaderSink extends ConstructorOrStaticMethodSink { }

  private class ResourceReaderDeserializeMethodSink extends ResourceReaderSink {
    ResourceReaderDeserializeMethodSink() {
      exists(Call mc, Constructor m |
        isResourceReaderCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** BinaryMessageFormatter */
  private predicate isBinaryMessageFormatterCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof BinaryMessageFormatterReadMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class BinaryMessageFormatterSink extends InstanceMethodSink { }

  private class BinaryMessageFormatterDeserializeMethodSink extends BinaryMessageFormatterSink {
    BinaryMessageFormatterDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isBinaryMessageFormatterCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** XamlReader */
  private predicate isXamlReaderCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof XamlReaderParseMethod
      or
      m instanceof XamlReaderLoadMethod
      or
      m instanceof XamlReaderLoadAsyncMethod
    ) and
    not mc.getArgument(0).hasValue()
  }

  private abstract class XamlReaderSink extends ConstructorOrStaticMethodSink { }

  private class XamlReaderDeserializeMethodSink extends XamlReaderSink {
    XamlReaderDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isXamlReaderCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** ProxyObject */
  private predicate isProxyObjectCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    (
      m instanceof ProxyObjectDecodeValueMethod
      or
      m instanceof ProxyObjectDecodeSerializedObjectMethod
    ) and
    not mc.getArgument(0).hasValue()
  }

  private abstract class ProxyObjectSink extends InstanceMethodSink { }

  private class ProxyObjectDeserializeMethodSink extends ProxyObjectSink {
    ProxyObjectDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isProxyObjectCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** SweetJayson */
  private predicate isSweetJaysonCall(MethodCall mc, Method m) {
    m = mc.getTarget() and
    m instanceof JaysonConverterToObjectMethod and
    not mc.getArgument(0).hasValue()
  }

  private abstract class SweetJaysonSink extends ConstructorOrStaticMethodSink { }

  private class SweetJaysonDeserializeMethodSink extends SweetJaysonSink {
    SweetJaysonDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        isSweetJaysonCall(mc, m) and
        this.asExpr() = mc.getArgument(0)
      )
    }
  }

  /** ServiceStack.Text.JsonSerializer */
  private abstract class ServiceStackTextJsonSerializerSink extends ConstructorOrStaticMethodSink { }

  private class ServiceStackTextJsonSerializerDeserializeMethodSink extends ServiceStackTextJsonSerializerSink {
    ServiceStackTextJsonSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        m = mc.getTarget() and
        (
          m instanceof ServiceStackTextJsonSerializerDeserializeFromStringMethod
          or
          m instanceof ServiceStackTextJsonSerializerDeserializeFromReaderMethod
          or
          m instanceof ServiceStackTextJsonSerializerDeserializeFromStreamMethod
        ) and
        not mc.getAnArgument().hasValue() and
        not mc.getAnArgument() instanceof TypeofExpr and
        this.asExpr() = mc.getAnArgument()
      )
    }
  }

  /** ServiceStack.Text.TypeSerializer */
  private abstract class ServiceStackTextTypeSerializerSink extends ConstructorOrStaticMethodSink { }

  private class ServiceStackTextTypeSerializerDeserializeMethodSink extends ServiceStackTextTypeSerializerSink {
    ServiceStackTextTypeSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        m = mc.getTarget() and
        (
          m instanceof ServiceStackTextTypeSerializerDeserializeFromStringMethod
          or
          m instanceof ServiceStackTextTypeSerializerDeserializeFromReaderMethod
          or
          m instanceof ServiceStackTextTypeSerializerDeserializeFromStreamMethod
        ) and
        not mc.getAnArgument().hasValue() and
        not mc.getAnArgument() instanceof TypeofExpr and
        this.asExpr() = mc.getAnArgument()
      )
    }
  }

  /** ServiceStack.Text.CsvSerializer */
  private abstract class ServiceStackTextCsvSerializerSink extends ConstructorOrStaticMethodSink { }

  private class ServiceStackTextCsvSerializerDeserializeMethodSink extends ServiceStackTextCsvSerializerSink {
    ServiceStackTextCsvSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        m = mc.getTarget() and
        (
          m instanceof ServiceStackTextCsvSerializerDeserializeFromStringMethod
          or
          m instanceof ServiceStackTextCsvSerializerDeserializeFromReaderMethod
          or
          m instanceof ServiceStackTextCsvSerializerDeserializeFromStreamMethod
        ) and
        not mc.getAnArgument().hasValue() and
        not mc.getAnArgument() instanceof TypeofExpr and
        this.asExpr() = mc.getAnArgument()
      )
    }
  }

  /** ServiceStack.Text.XmlSerializer */
  private abstract class ServiceStackTextXmlSerializerSink extends ConstructorOrStaticMethodSink { }

  private class ServiceStackTextXmlSerializerDeserializeMethodSink extends ServiceStackTextXmlSerializerSink {
    ServiceStackTextXmlSerializerDeserializeMethodSink() {
      exists(MethodCall mc, Method m |
        m = mc.getTarget() and
        (
          m instanceof ServiceStackTextXmlSerializerDeserializeFromStringMethod
          or
          m instanceof ServiceStackTextXmlSerializerDeserializeFromReaderMethod
          or
          m instanceof ServiceStackTextXmlSerializerDeserializeFromStreamMethod
        ) and
        not mc.getAnArgument().hasValue() and
        not mc.getAnArgument() instanceof TypeofExpr and
        this.asExpr() = mc.getAnArgument()
      )
    }
  }
}
