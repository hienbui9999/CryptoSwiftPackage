// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoSwiftPackage",
    platforms: [.macOS(.v10_15),.iOS(.v13),.tvOS(.v14),.watchOS(.v7)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        //.package(name:"ed25519vzsg",url: "https://github.com/vzsg/ed25519.git", from:"0.1.0"),
        .library(
            name: "CryptoSwiftPackage",
            targets: ["CryptoSwiftPackage"]),
    ],
    dependencies: [
        .package(name:"ed25519swift",url: "https://github.com/pebble8888/ed25519swift.git", from: "1.2.7"),
        .package(name:"secp256k1",url: "https://github.com/Boilertalk/secp256k1.swift.git", from: "0.1.0"),
        .package(name:"Blake2",url: "https://github.com/tesseract-one/Blake2.swift.git", from: "0.1.0"),
       
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "CryptoSwiftPackage",
            dependencies: ["ed25519swift","secp256k1","Blake2",]),
        .testTarget(
            name: "CryptoSwiftPackageTests",
            dependencies: ["CryptoSwiftPackage","ed25519swift","secp256k1","Blake2",]),
    ]
)
