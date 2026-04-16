plugins {
    kotlin("jvm") version "2.0.21"
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("TransferGuiKt")
}
