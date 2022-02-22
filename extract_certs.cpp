#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#endif

using std::string;

namespace {

const struct Certificate {
    unsigned int offset;
    unsigned int size;
    string filename;
    char pattern[4+1];
} kCertificates[] = {
    {0x92834, 1005, "clientca.pem", "\x30\x82\x03\xe9"},
    {0x92d38, 609, "clientcakey.pem", "\x30\x82\x02\x5d"},
    {0x92440, 897, "rootca.pem", "\x30\x82\x03\x7d"}
};

#ifdef _WIN32
#ifdef _UNICODE
std::wstring tstring(string str) {
	return std::wstring(str.begin(), str.end());
}
#else
#define tstring(x) x
#endif
#endif

void Message(const string& str) {
#ifdef _WIN32
    MessageBox(NULL, tstring(str).c_str(), _TEXT("Information"), MB_OK | MB_ICONINFORMATION);
#else
    printf("%s\n", str.c_str());
#endif
}

void Error(const string& str) {
#ifdef _WIN32
    MessageBox(NULL, tstring(str).c_str(), _TEXT("Error"), MB_OK | MB_ICONERROR);
#else
    fprintf(stderr, "%s\n", str.c_str());
#endif
}

void Usage() {
#ifdef _WIN32
    MessageBox(NULL, _TEXT("Drag and drop 00000011.app onto this application to proceed.\n"
                           "See https://dolphin-emu.org/docs/guides/wii-network-guide/ for more information."),
               _TEXT("Usage guide"), MB_OK | MB_ICONINFORMATION);
#else
    fprintf(stderr, "usage: extract_certs <00000011.app>\n");
#endif
}

void ReadWholeFile(FILE* fp, string* buffer) {
    size_t file_size;
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buffer->resize(file_size);
    fread(&(*buffer)[0], 1, file_size, fp);
}

string BuildOutputPath(const string& input, const string& fn) {
#ifdef _WIN32
    size_t pos = input.find_last_of('\\');
    if (pos == string::npos) {
        pos = input.find_last_of('/');
    }
#else
    size_t pos = input.find_last_of('/');
#endif

    if (pos == string::npos) {
        return fn;
    } else {
        string path = input;
        path.replace(pos + 1, string::npos, fn);
        return path;
    }
}

void WriteWholeFile(const string& filename, const string& data) {
	FILE* fp = nullptr;
#ifdef _MSC_VER
	fopen_s(&fp, filename.c_str(), "wb");
#else
	fp = fopen(filename.c_str(), "wb");
#endif
    fwrite(&data[0], 1, data.size(), fp);
    fclose(fp);
}

bool ExtractCerts(const string& input_filename, const string& buffer) {
    for (int i = 0; i < sizeof (kCertificates) / sizeof (kCertificates[0]); ++i) {
		const auto& cert = kCertificates[i];
        if (cert.offset + cert.size > buffer.size()) {
            return false;
        }
        string cert_data = buffer.substr(cert.offset, cert.size);
        if (memcmp(&cert_data[0], cert.pattern, 4)) {
            return false;
        }
        string out_path = BuildOutputPath(input_filename, cert.filename);
        WriteWholeFile(out_path, cert_data);
    }

    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        Usage();
        return 1;
    }

	FILE* fp = nullptr;
#ifdef _MSC_VER
	fopen_s(&fp, argv[1], "rb");
#else
	fp = fopen(argv[1], "rb");
#endif
    if (!fp) {
        Error("Unable to open the specified file.");
        return 1;
    }

    string buffer;
    ReadWholeFile(fp, &buffer);
    if (ExtractCerts(argv[1], buffer)) {
        Message("Certificates extracted! The required .pem files were created next to the input file.");
    } else {
        Error("Unable to extract the certificates!");
    }

    fclose(fp);
    return 0;
}
