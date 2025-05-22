# Imports
import pypandoc

# Paths
source_path = "./"
dest_path = "../deliverables/"
img_path = dest_path

# Conversion
output = pypandoc.convert_file(
    f"{source_path}summary_report.md",
    'pdf',
    outputfile=f"{dest_path}summary_report.pdf",
    extra_args=[
        '--pdf-engine=xelatex',
        '--wrap=auto',
        '--columns=80',
        f"--resource-path={img_path}"
    ]
)