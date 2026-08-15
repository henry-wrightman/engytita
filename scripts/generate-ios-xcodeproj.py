#!/usr/bin/env python3
"""Generate a minimal Xcode project for the Engytita iOS reference demo."""

from __future__ import annotations

import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "ios" / "Demo"
PROJ = DEMO / "EngytitaDemo.xcodeproj"


def uid() -> str:
    return uuid.uuid4().hex[:24].upper()


ids = {name: uid() for name in [
    "project", "target", "sources", "frameworks", "resources",
    "app_fr", "app_bf", "content_fr", "content_bf", "model_fr", "model_bf",
    "ble_fr", "ble_bf", "crypto_fr", "crypto_bf", "ffi_fr", "ffi_bf",
    "info_fr", "xc_fr", "xc_bf", "product",
    "proj_debug", "proj_release", "tgt_debug", "tgt_release",
    "proj_bcl", "tgt_bcl", "root_group", "app_group", "products_group",
]}

pbx = f'''// !$*UTF8*$!
{{
	archiveVersion = 1;
	classes = {{
	}};
	objectVersion = 56;
	objects = {{

/* Begin PBXBuildFile section */
		{ids["app_bf"]} /* EngytitaDemoApp.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["app_fr"]} /* EngytitaDemoApp.swift */; }};
		{ids["content_bf"]} /* ContentView.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["content_fr"]} /* ContentView.swift */; }};
		{ids["model_bf"]} /* DemoModel.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["model_fr"]} /* DemoModel.swift */; }};
		{ids["ble_bf"]} /* BleStack.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["ble_fr"]} /* BleStack.swift */; }};
		{ids["crypto_bf"]} /* DemoCrypto.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["crypto_fr"]} /* DemoCrypto.swift */; }};
		{ids["ffi_bf"]} /* EngytitaFfi.swift in Sources */ = {{isa = PBXBuildFile; fileRef = {ids["ffi_fr"]} /* EngytitaFfi.swift */; }};
		{ids["xc_bf"]} /* EngytitaFfi.xcframework in Frameworks */ = {{isa = PBXBuildFile; fileRef = {ids["xc_fr"]} /* EngytitaFfi.xcframework */; }};
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
		{ids["product"]} /* EngytitaDemo.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = EngytitaDemo.app; sourceTree = BUILT_PRODUCTS_DIR; }};
		{ids["app_fr"]} /* EngytitaDemoApp.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = EngytitaDemoApp.swift; sourceTree = "<group>"; }};
		{ids["content_fr"]} /* ContentView.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = ContentView.swift; sourceTree = "<group>"; }};
		{ids["model_fr"]} /* DemoModel.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = DemoModel.swift; sourceTree = "<group>"; }};
		{ids["ble_fr"]} /* BleStack.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = BleStack.swift; sourceTree = "<group>"; }};
		{ids["crypto_fr"]} /* DemoCrypto.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = DemoCrypto.swift; sourceTree = "<group>"; }};
		{ids["ffi_fr"]} /* EngytitaFfi.swift */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; name = EngytitaFfi.swift; path = ../../Engytita/Generated/EngytitaFfi.swift; sourceTree = "<group>"; }};
		{ids["xc_fr"]} /* EngytitaFfi.xcframework */ = {{isa = PBXFileReference; lastKnownFileType = wrapper.xcframework; path = Native/EngytitaFfi.xcframework; sourceTree = "<group>"; }};
		{ids["info_fr"]} /* Info.plist */ = {{isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>"; }};
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
		{ids["frameworks"]} /* Frameworks */ = {{
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
				{ids["xc_bf"]} /* EngytitaFfi.xcframework in Frameworks */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
		{ids["root_group"]} = {{
			isa = PBXGroup;
			children = (
				{ids["app_group"]} /* EngytitaDemo */,
				{ids["products_group"]} /* Products */,
				{ids["xc_fr"]} /* EngytitaFfi.xcframework */,
			);
			sourceTree = "<group>";
		}};
		{ids["app_group"]} /* EngytitaDemo */ = {{
			isa = PBXGroup;
			children = (
				{ids["app_fr"]} /* EngytitaDemoApp.swift */,
				{ids["content_fr"]} /* ContentView.swift */,
				{ids["model_fr"]} /* DemoModel.swift */,
				{ids["ble_fr"]} /* BleStack.swift */,
				{ids["crypto_fr"]} /* DemoCrypto.swift */,
				{ids["ffi_fr"]} /* EngytitaFfi.swift */,
				{ids["info_fr"]} /* Info.plist */,
			);
			path = EngytitaDemo;
			sourceTree = "<group>";
		}};
		{ids["products_group"]} /* Products */ = {{
			isa = PBXGroup;
			children = (
				{ids["product"]} /* EngytitaDemo.app */,
			);
			name = Products;
			sourceTree = "<group>";
		}};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
		{ids["target"]} /* EngytitaDemo */ = {{
			isa = PBXNativeTarget;
			buildConfigurationList = {ids["tgt_bcl"]} /* Build configuration list for PBXNativeTarget "EngytitaDemo" */;
			buildPhases = (
				{ids["sources"]} /* Sources */,
				{ids["frameworks"]} /* Frameworks */,
				{ids["resources"]} /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = EngytitaDemo;
			productName = EngytitaDemo;
			productReference = {ids["product"]} /* EngytitaDemo.app */;
			productType = "com.apple.product-type.application";
		}};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
		{ids["project"]} /* Project object */ = {{
			isa = PBXProject;
			attributes = {{
				BuildIndependentTargetsInParallel = 1;
				LastSwiftUpdateCheck = 1600;
				LastUpgradeCheck = 1600;
			}};
			buildConfigurationList = {ids["proj_bcl"]} /* Build configuration list for PBXProject "EngytitaDemo" */;
			compatibilityVersion = "Xcode 14.0";
			developmentRegion = en;
			hasScannedForEncodings = 0;
			knownRegions = (
				en,
				Base,
			);
			mainGroup = {ids["root_group"]};
			productRefGroup = {ids["products_group"]} /* Products */;
			projectDirPath = "";
			projectRoot = "";
			targets = (
				{ids["target"]} /* EngytitaDemo */,
			);
		}};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
		{ids["resources"]} /* Resources */ = {{
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
		{ids["sources"]} /* Sources */ = {{
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
				{ids["app_bf"]} /* EngytitaDemoApp.swift in Sources */,
				{ids["content_bf"]} /* ContentView.swift in Sources */,
				{ids["model_bf"]} /* DemoModel.swift in Sources */,
				{ids["ble_bf"]} /* BleStack.swift in Sources */,
				{ids["crypto_bf"]} /* DemoCrypto.swift in Sources */,
				{ids["ffi_bf"]} /* EngytitaFfi.swift in Sources */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		}};
/* End PBXSourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
		{ids["proj_debug"]} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
				ALWAYS_SEARCH_USER_PATHS = NO;
				CLANG_ENABLE_MODULES = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = dwarf;
				ENABLE_TESTABILITY = YES;
				GCC_DYNAMIC_NO_PIC = NO;
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				ONLY_ACTIVE_ARCH = YES;
				SDKROOT = iphoneos;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = "DEBUG";
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			}};
			name = Debug;
		}};
		{ids["proj_release"]} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
				ALWAYS_SEARCH_USER_PATHS = NO;
				CLANG_ENABLE_MODULES = YES;
				COPY_PHASE_STRIP = NO;
				DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
				IPHONEOS_DEPLOYMENT_TARGET = 17.0;
				SDKROOT = iphoneos;
				SWIFT_COMPILATION_MODE = wholemodule;
			}};
			name = Release;
		}};
		{ids["tgt_debug"]} /* Debug */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = EngytitaDemo/Info.plist;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/Frameworks",
				);
				MARKETING_VERSION = 0.1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.engytita.EngytitaDemo;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = "1,2";
				FRAMEWORK_SEARCH_PATHS = (
					"$(inherited)",
					"$(PROJECT_DIR)/Native",
				);
				OTHER_LDFLAGS = (
					"$(inherited)",
					"-lc++",
				);
			}};
			name = Debug;
		}};
		{ids["tgt_release"]} /* Release */ = {{
			isa = XCBuildConfiguration;
			buildSettings = {{
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = NO;
				INFOPLIST_FILE = EngytitaDemo/Info.plist;
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/Frameworks",
				);
				MARKETING_VERSION = 0.1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.engytita.EngytitaDemo;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SWIFT_VERSION = 5.0;
				TARGETED_DEVICE_FAMILY = "1,2";
				FRAMEWORK_SEARCH_PATHS = (
					"$(inherited)",
					"$(PROJECT_DIR)/Native",
				);
				OTHER_LDFLAGS = (
					"$(inherited)",
					"-lc++",
				);
			}};
			name = Release;
		}};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
		{ids["proj_bcl"]} /* Build configuration list for PBXProject "EngytitaDemo" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{ids["proj_debug"]} /* Debug */,
				{ids["proj_release"]} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
		{ids["tgt_bcl"]} /* Build configuration list for PBXNativeTarget "EngytitaDemo" */ = {{
			isa = XCConfigurationList;
			buildConfigurations = (
				{ids["tgt_debug"]} /* Debug */,
				{ids["tgt_release"]} /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		}};
/* End XCConfigurationList section */
	}};
	rootObject = {ids["project"]} /* Project object */;
}}
'''

PROJ.mkdir(parents=True, exist_ok=True)
(PROJ / "project.pbxproj").write_text(pbx)

scheme_dir = PROJ / "xcshareddata" / "xcschemes"
scheme_dir.mkdir(parents=True, exist_ok=True)
(scheme_dir / "EngytitaDemo.xcscheme").write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme
   LastUpgradeVersion = "1600"
   version = "1.7">
   <BuildAction
      parallelizeBuildables = "YES"
      buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry
            buildForTesting = "YES"
            buildForRunning = "YES"
            buildForProfiling = "YES"
            buildForArchiving = "YES"
            buildForAnalyzing = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{ids["target"]}"
               BuildableName = "EngytitaDemo.app"
               BlueprintName = "EngytitaDemo"
               ReferencedContainer = "container:EngytitaDemo.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <LaunchAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      launchStyle = "0"
      useCustomWorkingDirectory = "NO"
      ignoresPersistentStateOnLaunch = "NO"
      debugDocumentVersioning = "YES"
      debugServiceExtension = "internal"
      allowLocationSimulation = "YES">
      <BuildableProductRunnable
         runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{ids["target"]}"
            BuildableName = "EngytitaDemo.app"
            BlueprintName = "EngytitaDemo"
            ReferencedContainer = "container:EngytitaDemo.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
</Scheme>
''')

print(f"Wrote {PROJ / 'project.pbxproj'}")
print(f"Wrote {scheme_dir / 'EngytitaDemo.xcscheme'}")
