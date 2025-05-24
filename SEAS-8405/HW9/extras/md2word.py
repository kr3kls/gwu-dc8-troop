import pypandoc

output = pypandoc.convert_file(
    'summary_report.md',
    'docx',
    outputfile='summary_report.docx',
    extra_args=[
        '--from=markdown+raw_html+table_captions+yaml_metadata_block+implicit_figures',
        '--resource-path=.:../deliverables'
    ]
)