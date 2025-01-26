Java.perform(function () {
    console.log("Starting Frida script...");

    // ===== Hook ClassLoader to Detect Dynamic Class Loading =====
    console.log("[*] Hooking ClassLoader to monitor for dynamic loading of com.adc.sensorComms...");

    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload("java.lang.String").implementation = function (className) {
        console.log("[*] ClassLoader.loadClass called for: " + className);

        // Check if the target class is being loaded
        if (className === "com.adc.sensorComms") {
            console.log("[*] Target class com.adc.sensorComms is being loaded. Setting up hooks...");

            // Call the original loadClass method
            var loadedClass = this.loadClass(className);

            // Delay to ensure the class is fully loaded
            Java.scheduleOnMainThread(function () {
                hookSensorComms(); // Set up hooks for the class
            });

            return loadedClass;
        }

        return this.loadClass(className);
    };

    // ===== Hook com.adc.sensorComms Methods Dynamically =====
    function hookSensorComms() {
        try {
            var SensorCommsClass = Java.use('com.adc.sensorComms');
            console.log("[*] Successfully hooked com.adc.sensorComms class.");

            // List all methods dynamically
            console.log("[*] Listing methods in com.adc.sensorComms:");
            var methods = SensorCommsClass.class.getDeclaredMethods();
            methods.forEach(function (method) {
                console.log(" - Method: " + method.getName());
            });

            // Hook each method dynamically
            methods.forEach(function (method) {
                try {
                    var methodName = method.getName();
                    console.log("[*] Hooking method: " + methodName);

                    SensorCommsClass[methodName].overloads.forEach(function (overload) {
                        overload.implementation = function () {
                            console.log("[*] Method called: " + methodName);

                            // Log arguments passed to the method
                            for (var i = 0; i < arguments.length; i++) {
                                console.log("   Arg[" + i + "]: " + arguments[i]);
                            }

                            // Call the original method
                            var result = overload.apply(this, arguments);

                            // Log the return value
                            console.log("   Return value: " + result);

                            return result;
                        };
                    });
                } catch (e) {
                    console.log("[!] Error hooking method " + method.getName() + ": " + e.message);
                }
            });

        } catch (e) {
            console.log("[!] Error hooking com.adc.sensorComms: " + e.message);
        }
    }

    console.log("[*] Waiting for com.adc.sensorComms to load...");
});
