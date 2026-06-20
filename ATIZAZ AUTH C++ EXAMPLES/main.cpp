#include <iostream>
#include <string>
#include "AtizazAuth.h"

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Welcome to Atizaz Auth C++ Example  " << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n[+] Initializing with server..." << std::endl;

    AtizazAuthAPI api(
        "https://cmatizaz-cfire.atizazfayaz78.workers.dev",
        "ENTER SECRET", 
        "ENTER NAME",
        "1.0"
    );

    api.Init();

    std::cout << "[+] Initialization Success! Session ID: " << api.GetSessionID() << std::endl;
    std::cout << "[+] Hardware ID: " << AtizazAuthAPI::GetHWID() << std::endl;

    while (true) {
        std::cout << "\n------------------------------\n";
        std::cout << "1. Login (Username/Password)\n";
        std::cout << "2. Register\n";
        std::cout << "3. License Only Login\n";
        std::cout << "4. Exit\n";
        std::cout << "------------------------------\n";
        std::cout << "Enter your choice: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            std::string username, password;
            std::cout << "Username: "; std::getline(std::cin, username);
            std::cout << "Password: "; std::getline(std::cin, password);

            json resp = api.Login(username, password);
            if (resp.value("success", false)) {
                std::cout << "\n[SUCCESS] Login Authenticated!\n";
                std::cout << " > User: " << resp.value("username", "") << "\n";
                std::cout << " > Subscription: " << resp.value("subscription", "") << "\n";
                std::cout << " > Expiry: " << resp.value("expiry", "") << "\n";
            } else {
                std::cout << "\n[ERROR] Login Failed: " << resp.value("message", "") << "\n";
            }
        } else if (choice == "2") {
            std::string username, password, license_key;
            std::cout << "Username: "; std::getline(std::cin, username);
            std::cout << "Password: "; std::getline(std::cin, password);
            std::cout << "License Key: "; std::getline(std::cin, license_key);

            json resp = api.Register(username, password, license_key);
            if (resp.value("success", false)) {
                std::cout << "\n[SUCCESS] Account Registered! You can now login.\n";
            } else {
                std::cout << "\n[ERROR] Registration Failed: " << resp.value("message", "") << "\n";
            }
        } else if (choice == "3") {
            std::string license_key;
            std::cout << "License Key: "; std::getline(std::cin, license_key);

            json resp = api.License(license_key);
            if (resp.value("success", false)) {
                std::cout << "\n[SUCCESS] License Authenticated!\n";
                std::cout << " > Subscription: " << resp.value("subscription", "") << "\n";
                std::cout << " > Expiry: " << resp.value("expiry", "") << "\n";
            } else {
                std::cout << "\n[ERROR] Login Failed: " << resp.value("message", "") << "\n";
            }
        } else if (choice == "4") {
            std::cout << "Exiting...\n";
            break;
        } else {
            std::cout << "Invalid choice, please select 1-4.\n";
        }
    }

    return 0;
}
