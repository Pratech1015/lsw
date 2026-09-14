class Lsw < Formula
  desc "Linux Subsystem for Windows - run Windows 11 apps on Linux"
  homepage "https://github.com/lsw-project/lsw"
  url "https://github.com/lsw-project/lsw/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "SKIP"
  license "GPL-3.0-or-later"
  head "https://github.com/lsw-project/lsw.git", branch: "main"

  depends_on "gcc" => :build
  depends_on "make" => :build

  def install
    system "make", "PREFIX=#{prefix}"
    system "make", "PREFIX=#{prefix}", "install"
  end

  test do
    assert_match "LSW", shell_output("#{bin}/lsw --version")
  end
end