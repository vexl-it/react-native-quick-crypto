
#include "MGLCreateCipherInstaller.h"

#include <memory>

#include "MGLCipherHostObject.h"
#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

namespace margelo {

FieldDefinition getCreateECDHFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) {
  return buildPair(
      "createECDH", JSIF([=]) {
        if (count < 1) {
          throw jsi::JSError(runtime, "Params object is required");
        }

        if (!arguments[0].isObject()) {
          throw jsi::JSError(runtime,
                             "createCipher: Params needs to be an object");
        }

        auto params = arguments[0].getObject(runtime);

        if (!params.hasProperty(runtime, "curve_name")) {
          throw jsi::JSError(runtime, "createECDH: curve_name is required");
        }

        auto curve_name = params.getProperty(runtime, "curve_name")
                               .asString(runtime)
                               .utf8(runtime);


        auto hostObject = std::make_shared<MGLCipherHostObject>(
           curve_name, runtime, jsCallInvoker, workerQueue);

        return jsi::Object::createFromHostObject(runtime, hostObject);
      });
}
}  // namespace margelo
