import os
import yara

class ApexYaraScanner:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.compiled_rules = self._compile_rules()

    def _compile_rules(self):
        """Compiles all .yar and .yara files found in the rules directory."""
        rules_dict = {}
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return None

        for file in os.listdir(self.rules_dir):
            if file.endswith(".yar") or file.endswith(".yara"):
                rules_dict[file] = os.path.join(self.rules_dir, file)

        try:
            if rules_dict:
                return yara.compile(filepaths=rules_dict)
        except Exception as e:
            print(f"[!] Warning: Failed to compile YARA rules: {e}")
        return None

    def scan_file(self, filepath):
        """Scans a given file path against compiled YARA rules."""
        if not self.compiled_rules or not os.path.exists(filepath):
            return []
        try:
            matches = self.compiled_rules.match(filepath)
            return [match.rule for match in matches]
        except Exception as e:
            return [f"Scan Error: {str(e)}"]
