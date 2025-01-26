Java.perform(function () {
    console.log("Starting Frida script for com.adc.sensorComms...");

    try {
        // ===== Hook the Target Class =====
        var SensorCommsClass = Java.use('com.adc.sensorComms');
        console.log("[*] Hooked com.adc.sensorComms class.");

        // ===== List All Methods =====
        console.log("[*] Listing all methods in com.adc.sensorComms:");
        var methods = SensorCommsClass.class.getDeclaredMethods();
        methods.forEach(function (method) {
            console.log(" - Method: " + method.getName());
        });

        // ===== Dynamically Hook All Methods =====
        methods.forEach(function (method) {
            try {
                var methodName = method.getName();
                console.log("[*] Hooking method: " + methodName);

                // Hook the method dynamically
                SensorCommsClass[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log("[*] Method called: " + methodName);

                        // Log all arguments passed to the method
                        for (var i = 0; i < arguments.length; i++) {
                            console.log("   Arg[" + i + "]: " + arguments[i]);
                        }

                        // Call the original method
                        var result = overload.apply(this, arguments);

                        // Log the return value
                        console.log("   Return value: " + result);

                        // Dump all static fields for this method's class
                        dumpStaticFields(SensorCommsClass);

                        return result;
                    };
                });
            } catch (e) {
                console.log("[!] Error hooking method " + method.getName() + ": " + e.message);
            }
        });

        // ===== Dump Static Fields =====
        function dumpStaticFields(targetClass) {
            console.log("[*] Dumping static fields for " + targetClass.$className + ":");
            var fields = targetClass.class.getDeclaredFields();
            fields.forEach(function (field) {
                try {
                    field.setAccessible(true); // Make private fields accessible
                    var fieldName = field.getName();
                    var fieldValue = field.get(null); // null because static fields belong to the class, not an instance
                    console.log("   Static Field: " + fieldName + " = " + fieldValue);
                } catch (e) {
                    console.log("   [!] Error accessing field: " + e.message);
                }
            });
        }

    } catch (e) {
        console.log("[!] Error in script: " + e.message);
    }
});
