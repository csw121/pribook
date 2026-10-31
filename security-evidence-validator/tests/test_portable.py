import argparse
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, Mock
from tools import windows_launcher as launcher
from sev.cli import main
from sev.common import read_json
from sev.text_analyzer import analyze_text, render_review_html
from tests.test_text_analyzer import REVIEW, response
from tests.support import ROOT

class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'한글 공백 프로젝트';self.root.mkdir()
        self.patch=patch.object(launcher,'ROOT',self.root);self.patch.start();self.addCleanup(self.patch.stop)
        self.out=io.StringIO();self.capture=redirect_stdout(self.out);self.capture.__enter__();self.addCleanup(self.capture.__exit__,None,None,None)
    def args(self,**kwargs):return argparse.Namespace(input=None,encoding='utf-8-sig',context=None,**kwargs)
    def test_bootstrap_needs_no_site_packages(self):
        r=subprocess.run([sys.executable,'-S',str(ROOT/'tools/windows_launcher.py'),'--help'],cwd=self.root,capture_output=True)
        self.assertEqual(r.returncode,0)
    def test_platform_python_path(self):
        with patch.object(launcher,'WINDOWS',True):self.assertEqual(launcher.environment_python(),self.root/'.venv/Scripts/python.exe')
        with patch.object(launcher,'WINDOWS',False):self.assertEqual(launcher.environment_python(),self.root/'.venv/bin/python')
    def test_process_uses_project_root_and_argument_list(self):
        with patch.object(launcher.subprocess,'run',return_value=Mock(returncode=7)) as run:
            self.assertEqual(launcher.run([self.root/'python.exe',self.root/'자료 파일.txt']),7)
        self.assertEqual(run.call_args.kwargs['cwd'],self.root);self.assertFalse(run.call_args.kwargs['check'])
        self.assertEqual(run.call_args.args[0][1],str(self.root/'자료 파일.txt'));self.assertNotIn('shell',run.call_args.kwargs)
    def test_process_failure_is_actionable(self):
        with patch.object(launcher.subprocess,'run',side_effect=OSError()):self.assertEqual(launcher.run(['missing']),2)
        self.assertIn('01_setup.cmd',self.out.getvalue())
    def test_missing_environment_points_to_setup(self):
        self.assertIsNone(launcher.require_environment());self.assertIn('01_setup.cmd',self.out.getvalue())
    def test_missing_dependency_points_to_setup(self):
        with patch.object(launcher,'usable_python',return_value=True),patch.object(launcher,'run',return_value=1):self.assertIsNone(launcher.require_environment())
    def test_setup_creates_venv_and_folders(self):
        with patch.object(launcher,'usable_python',return_value=False),patch.object(launcher.venv,'EnvBuilder') as builder,patch.object(launcher,'run',return_value=0) as run,patch.object(launcher,'check',return_value=0):
            self.assertEqual(launcher.setup(),0)
        builder.assert_called_once_with(with_pip=True);builder.return_value.create.assert_called_once_with(self.root/'.venv')
        self.assertTrue((self.root/'private/input_txt').is_dir());self.assertTrue((self.root/'output').is_dir())
        self.assertIn(self.root/'requirements.txt',run.call_args.args[0])
    def test_repeated_setup_preserves_private_data(self):
        launcher.folders();p=self.root/'private/input_txt/자료.txt';p.write_text('보존할 자료')
        with patch.object(launcher,'usable_python',return_value=True),patch.object(launcher.venv,'EnvBuilder') as builder,patch.object(launcher,'run',return_value=0),patch.object(launcher,'check',return_value=0):
            self.assertEqual(launcher.setup(),0);self.assertEqual(launcher.setup(),0)
        builder.assert_not_called();self.assertEqual(p.read_text(),'보존할 자료')
    def test_missing_pip_uses_ensurepip(self):
        with patch.object(launcher,'usable_python',return_value=True),patch.object(launcher,'run',side_effect=[1,0,0]) as run,patch.object(launcher,'check',return_value=0):self.assertEqual(launcher.setup(),0)
        self.assertIn('ensurepip',run.call_args_list[1].args[0])
    def test_package_install_failure_stops_setup(self):
        with patch.object(launcher,'usable_python',return_value=True),patch.object(launcher,'run',side_effect=[0,1]),patch.object(launcher,'check') as check:self.assertEqual(launcher.setup(),2)
        check.assert_not_called()
    def test_old_python_is_rejected(self):
        with patch.object(launcher.sys,'version_info',(3,12)):self.assertEqual(launcher.setup(),2)
    def test_broken_existing_venv_not_removed(self):
        python=launcher.environment_python();python.parent.mkdir(parents=True);python.write_text('preserve')
        with patch.object(launcher,'usable_python',return_value=False),patch.object(launcher.venv,'EnvBuilder') as builder:self.assertEqual(launcher.setup(),2)
        builder.assert_not_called();self.assertEqual(python.read_text(),'preserve')
    def test_model_failure_is_actionable(self):
        with patch.object(launcher,'run',return_value=2):self.assertEqual(launcher.check(self.root/'python'),2)
        self.assertIn('ollama pull qwen3.5:9b',self.out.getvalue())
    def test_empty_input_opens_folder_and_stops_before_ai(self):
        with patch.object(launcher,'require_environment',return_value=self.root/'python'),patch.object(launcher,'open_file',return_value=0) as open_file,patch.object(launcher,'check') as check,patch.object(launcher,'run') as run:
            self.assertEqual(launcher.analyze(self.args()),2)
        open_file.assert_called_once_with(self.root/'private/input_txt');check.assert_not_called();run.assert_not_called()
    def test_failed_analysis_does_not_open_old_result(self):
        launcher.folders();(self.root/'private/input_txt/test.txt').write_text('data');(self.root/'output/text_review.html').write_text('old')
        with patch.object(launcher,'require_environment',return_value=self.root/'python'),patch.object(launcher,'check',return_value=0),patch.object(launcher,'run',return_value=2),patch.object(launcher,'open_results') as open_results:
            self.assertEqual(launcher.analyze(self.args()),2)
        open_results.assert_not_called()
    def test_success_uses_project_paths_context_encoding_and_opens_result(self):
        launcher.folders();(self.root/'private/input_txt/test.TXT').write_text('data')
        args=self.args();args.context=4096;args.encoding='cp949'
        with patch.object(launcher,'require_environment',return_value=self.root/'python'),patch.object(launcher,'check',return_value=0),patch.object(launcher,'run',return_value=0) as run,patch.object(launcher,'open_results',return_value=0) as open_results:
            self.assertEqual(launcher.analyze(args),0)
        command=run.call_args.args[0];self.assertIn(self.root/'private/input_txt',command);self.assertIn('4096',command);self.assertIn('cp949',command);open_results.assert_called_once()
    def test_relative_custom_input_uses_project_root(self):
        source=self.root/'별도 폴더';source.mkdir();(source/'test.txt').write_text('data');args=self.args();args.input='별도 폴더'
        with patch.object(launcher,'require_environment',return_value=self.root/'python'),patch.object(launcher,'check',return_value=0),patch.object(launcher,'run',return_value=0) as run,patch.object(launcher,'open_results',return_value=0):self.assertEqual(launcher.analyze(args),0)
        self.assertIn(source,run.call_args.args[0])
    def test_results_prefer_absolute_html_path(self):
        launcher.folders();(self.root/'output/text_review.md').write_text('md');html=self.root/'output/text_review.html';html.write_text('html')
        with patch.object(launcher,'open_file',return_value=0) as open_file:self.assertEqual(launcher.open_results(),0)
        open_file.assert_called_once_with(html)
    def test_no_result_is_explained(self):self.assertEqual(launcher.open_results(),2)
    def test_windows_open_uses_native_absolute_path(self):
        file=self.root/'자료 파일.html';file.write_text('safe')
        with patch.object(launcher,'WINDOWS',True),patch.object(launcher.os,'startfile',create=True) as start:self.assertEqual(launcher.open_file(file),0)
        start.assert_called_once_with(str(file.resolve()))
    def test_window_open_failure_shows_path(self):
        with patch.object(launcher,'WINDOWS',True),patch.object(launcher.os,'startfile',create=True,side_effect=OSError()):self.assertEqual(launcher.open_file(self.root/'result.html'),2)
        self.assertIn(str(self.root/'result.html'),self.out.getvalue())

class PortableOutputTests(unittest.TestCase):
    def test_review_html_escapes_model_and_document_text(self):
        result={'run_id':'synthetic','input_hash':'abc','created_at':'2026-10-31T00:00:00+00:00','reviews':[{'source_id':'TEXT-001','character_start':0,'character_end':30,'summary':'<script>alert(1)</script>','claims':[],'questions':[]}]}
        html=render_review_html(result)
        self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html);self.assertIn('default-src',html);self.assertIn('2026-10-31',html)
    def test_cli_context_override_and_html_preserve_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);txt=root/'자료.txt';txt.write_text('다른 사용자 자료가 반환되었다.',encoding='utf-8')
            settings=ROOT/'config/settings.json';before=settings.read_bytes()
            with patch('sev.text_analyzer.local_request',return_value=response()) as request,redirect_stdout(io.StringIO()):
                code=main(['ai-text','--input',str(txt),'--settings',str(settings),'--context','4096','--output',str(root/'a.json'),'--markdown',str(root/'a.md'),'--html',str(root/'a.html')])
            self.assertEqual(code,0);self.assertEqual(request.call_args.args[2]['options']['num_ctx'],4096)
            self.assertTrue((root/'a.html').is_file());self.assertEqual(before,settings.read_bytes())

class DistributionTests(unittest.TestCase):
    def setUp(self):
        from tools import package_project
        self.packager=package_project
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'다른 PC 배포';self.root.mkdir()
        for name in package_project.ALLOWED:
            p=self.root/name
            if (ROOT/name).is_dir():p.mkdir()
            else:p.write_text('source',encoding='utf-8')
        self.patcher=patch.object(package_project,'ROOT',self.root);self.patcher.start();self.addCleanup(self.patcher.stop)
    def contents(self,path):
        from zipfile import ZipFile
        with ZipFile(path) as archive:
            self.assertIsNone(archive.testzip());return {n:archive.read(n) for n in archive.namelist()}
    def test_package_has_installers_and_lock_without_private_outputs_or_cache(self):
        for name in ['private/input.txt','output/result.json','.venv/python.exe','examples/private/secret.txt','examples/output/secret.txt','examples/__pycache__/x.pyc','examples/.env']:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('DO_NOT_SHIP')
        with redirect_stdout(io.StringIO()):self.packager.package(self.root/'delivery/project.zip')
        contents=self.contents(self.root/'delivery/project.zip')
        self.assertIn('Security-Evidence-Validator/01_setup.cmd',contents);self.assertIn('Security-Evidence-Validator/requirements-lock.txt',contents)
        self.assertFalse(any(b'DO_NOT_SHIP' in data for data in contents.values()))
    def test_external_symlink_not_included(self):
        target=Path(self.tmp.name)/'outside.txt';target.write_text('DO_NOT_SHIP')
        try:(self.root/'examples/link.txt').symlink_to(target)
        except (OSError,NotImplementedError):self.skipTest('이 PC에서는 심볼릭 링크 생성 권한/기능이 없습니다.')
        with redirect_stdout(io.StringIO()):self.packager.package(self.root/'project.zip')
        self.assertNotIn('Security-Evidence-Validator/examples/link.txt',self.contents(self.root/'project.zip'))
    def test_output_archive_cannot_include_itself(self):
        output=self.root/'examples/project.zip'
        with redirect_stdout(io.StringIO()):self.packager.package(output)
        self.assertNotIn('Security-Evidence-Validator/examples/project.zip',self.contents(output))
    def test_missing_launcher_blocks_release(self):
        (self.root/'01_setup.cmd').unlink()
        self.assertRaises(ValueError,self.packager.package,self.root/'project.zip')
