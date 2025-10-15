#include <cstddef>
#include <string>

#include "testlib.h"

static inline void trimTrailingSpaces(std::string& s) {
	size_t last = s.find_last_not_of(' ');
	if (last == std::string::npos) {
		s.clear();
	} else {
		s.resize(last + 1);
	}
}

int main(int argc, char** argv) {
	registerTestlibCmd(argc, argv);

	std::string line_ouf, line_ans;
	size_t line_num = 0;

	while (!ouf.eof() && !ans.eof()) {
		++line_num;
		ouf.readLineTo(line_ouf);
		ans.readLineTo(line_ans);

		trimTrailingSpaces(line_ouf);
		trimTrailingSpaces(line_ans);

		if (line_ouf != line_ans) {
			quitf(_wa, "Line %zu differs. Expected: `%s`, Found: `%s`", line_num,
			      compress(line_ans).c_str(), compress(line_ouf).c_str());
		}
	}

	while (!ouf.eof()) {
		++line_num;
		ouf.readLineTo(line_ouf);
		trimTrailingSpaces(line_ouf);
		if (!line_ouf.empty()) {
			quitf(_wa,
			      "Participant has extra non-blank lines. First extra data is on line %zu: `%s`",
			      line_num, compress(line_ouf).c_str());
		}
	}

	while (!ans.eof()) {
		++line_num;
		ans.readLineTo(line_ans);
		trimTrailingSpaces(line_ans);
		if (!line_ans.empty()) {
			quitf(
			    _wa,
			    "Participant has missing non-blank lines. First missing data is on line %zu: `%s`",
			    line_num, compress(line_ans).c_str());
		}
	}

	quitf(_ok, "%zu lines", line_num);
}