# Homebrew formula for Specter AI.
#
# Tap + install:
#   brew tap sam00/tap https://github.com/sam00/AI-Specter
#   brew install ai-specter
#
# Update `url`/`sha256` to the published PyPI sdist for each release. Resources
# for transitive deps are intentionally omitted here; `brew install` resolves
# them via the bundled virtualenv build below.
class AiSpecter < Formula
  include Language::Python::Virtualenv

  desc "AI-driven automated penetration testing from your terminal"
  homepage "https://sam00.github.io/AI-Specter/"
  url "https://files.pythonhosted.org/packages/source/a/ai-specter/ai_specter-0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "Specter", shell_output("#{bin}/specter version")
  end
end
