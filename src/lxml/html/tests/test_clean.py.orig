import unittest
from lxml.tests.common_imports import make_doctest

import lxml.html
from lxml.html.clean import Cleaner, clean_html


class CleanerTest(unittest.TestCase):
    def test_allow_tags(self):
        html = """
            <html>
            <head>
            </head>
            <body>
            <p>some text</p>
            <table>
            <tr>
            <td>hello</td><td>world</td>
            </tr>
            <tr>
            <td>hello</td><td>world</td>
            </tr>
            </table>
            <img>
            </body>
            </html>
            """

        html_root = lxml.html.document_fromstring(html)
        cleaner = Cleaner(
            remove_unknown_tags = False,
            allow_tags = ['table', 'tr', 'td'])
        result = cleaner.clean_html(html_root)

        self.assertEqual(12-5+1, len(list(result.iter())))

    def test_safe_attrs_included(self):
        html = """<p><span style="color: #00ffff;">Cyan</span></p>"""

        safe_attrs=set(lxml.html.defs.safe_attrs)
        safe_attrs.add('style')

        cleaner = Cleaner(
            safe_attrs_only=True,
            safe_attrs=safe_attrs)
        result = cleaner.clean_html(html)

        self.assertEqual(html, result)

    def test_safe_attrs_excluded(self):
        html = """<p><span style="color: #00ffff;">Cyan</span></p>"""
        expected = """<p><span>Cyan</span></p>"""

        safe_attrs=set()

        cleaner = Cleaner(
            safe_attrs_only=True,
            safe_attrs=safe_attrs)
        result = cleaner.clean_html(html)

        self.assertEqual(expected, result)

    def test_clean_invalid_root_tag(self):
        # only testing that cleaning with invalid root tags works at all
        s = lxml.html.fromstring('parent <invalid tag>child</another>')
        self.assertEqual('parent child', clean_html(s).text_content())

        s = lxml.html.fromstring('<invalid tag>child</another>')
        self.assertEqual('child', clean_html(s).text_content())

    def test_sneaky_noscript_in_style(self):
        # This gets parsed as <noscript> -> <style>"...</noscript>..."</style>
        # thus passing the </noscript> through into the output.
        html = '<noscript><style><a title="</noscript><img src=x onerror=alert(1)>">'
        s = lxml.html.fragment_fromstring(html)

        self.assertEqual(
            b'<noscript><style>/* deleted */</style></noscript>',
            lxml.html.tostring(clean_html(s)))

    def test_sneaky_import_in_style(self):
        # Prevent "@@importimport" -> "@import" replacement.
        style_codes = [
            "@@importimport(extstyle.css)",
            "@ @  import import(extstyle.css)",
            "@ @ importimport(extstyle.css)",
            "@@  import import(extstyle.css)",
            "@ @import import(extstyle.css)",
            "@@importimport()",
        ]
        for style_code in style_codes:
            html = '<style>%s</style>' % style_code
            s = lxml.html.fragment_fromstring(html)

            cleaned = lxml.html.tostring(clean_html(s))
            self.assertEqual(
                b'<style>/* deleted */</style>',
                cleaned,
                "%s  ->  %s" % (style_code, cleaned))

    def test_formaction_attribute_in_button_input(self):
        # The formaction attribute overrides the form's action and should be
        # treated as a malicious link attribute
        html = ('<form id="test"><input type="submit" formaction="javascript:alert(1)"></form>'
        '<button form="test" formaction="javascript:alert(1)">X</button>')
        expected = ('<div><form id="test"><input type="submit" formaction=""></form>'
        '<button form="test" formaction="">X</button></div>')
        cleaner = Cleaner(
            forms=False,
            safe_attrs_only=False,
        )
        self.assertEqual(
            expected,
            cleaner.clean_html(html))


def test_suite():
    suite = unittest.TestSuite()
    suite.addTests([make_doctest('test_clean.txt')])
    suite.addTests([make_doctest('test_clean_embed.txt')])
    suite.addTests(unittest.makeSuite(CleanerTest))
    return suite
