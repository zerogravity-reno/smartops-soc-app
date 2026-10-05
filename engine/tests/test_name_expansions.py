"""A name the narrative mentions expands to the files it stands for in the rows (B1c)."""

from contracts import ResultSet

from smartops.subagent_analysts.formatting import name_expansions

REAL = r"C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe"
FAKE = r"C:\Users\Administrator\Desktop\splunkd.exe"


def _procs(*rows):
    return [("processes", ResultSet(query="q", row_count=len(rows), rows=list(rows)))]


def test_one_name_for_two_files_lists_both_with_counts():
    sets = _procs({"ParentImage": REAL, "count": "20"}, {"ParentImage": FAKE, "count": "2"})
    lines = name_expansions("ran splunk-powershell.exe from splunkd.exe", sets)
    assert lines == [f'~ "splunkd.exe" in these rows is 2 files: {REAL}=20, {FAKE}=2']


def test_single_path_still_expands_and_unmentioned_names_do_not():
    sets = _procs({"ParentImage": FAKE}, {"ParentImage": r"C:\Windows\System32\svchost.exe"})
    assert name_expansions("children of splunkd", sets) == [f'~ "splunkd.exe" in these rows is 1 file: {FAKE}=1']


def test_bare_names_and_urls_expand_to_nothing():
    sets = _procs({"ParentImage": "splunkd.exe"}) + [
        ("uncategorised", ResultSet(query="q", row_count=1, rows=[{"url": "http://x.test/splunkd.exe"}]))
    ]
    assert name_expansions("from splunkd.exe", sets) == []
