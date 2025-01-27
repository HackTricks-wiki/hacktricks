import json
import os
import sys
import re
import logging
from os import path
from urllib.request import urlopen, Request

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(filename='hacktricks-preprocessor.log', mode='w', encoding='utf-8')
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

handler2 = logging.FileHandler(filename='hacktricks-preprocessor-error.log', mode='w', encoding='utf-8')
handler2.setLevel(logging.ERROR)
logger.addHandler(handler2)


def findtitle(search ,obj, key, path=(),):
    # logger.debug(f"Looking for {search} in {path}")
    if isinstance(obj, dict) and key in obj and obj[key] == search: 
        return obj, path
    if isinstance(obj, list):
        for k, v in enumerate(obj):
            item = findtitle(search, v, key, (*path, k))
            if item is not None:
                return item
    if isinstance(obj, dict):
        for k, v in obj.items():
            item = findtitle(search, v, key, (*path, k))
            if item is not None:
                return item


def ref(matchobj):
    logger.debug(f'Ref match: {matchobj.groups(0)[0].strip()}')
    href =  matchobj.groups(0)[0].strip()
    title = href
    if href.startswith("http://") or href.startswith("https://"):
        if context['config']['preprocessor']['hacktricks']['env'] == 'dev':
            pass
        else:
            try:
                raw_html = str(urlopen(Request(href, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0'})).read())
                match = re.search('<title>(.*?)</title>', raw_html)
                title = match.group(1) if match else href
            except Exception as e:
                logger.debug(f'Error opening URL {href}: {e}')
                pass #nDont stop on broken link
    else:
        try:
            if href.endswith("/"):
                href = href+"README.md" # Fix if ref points to a folder
            if "#" in  href:
                chapter, _path = findtitle(href.split("#")[0], book, "source_path")
                title = " ".join(href.split("#")[1].split("-")).title()
                logger.debug(f'Ref has # using title: {title}')
            else:
                chapter, _path = findtitle(href, book, "source_path")
                logger.debug(f'Recursive title search result: {chapter["name"]}')
                title = chapter['name']
        except Exception as e:
            try:
                dir = path.dirname(current_chapter['source_path'])
                logger.debug(f'Error getting chapter title: {href} trying with relative path {path.normpath(path.join(dir,href))}')
                if "#" in  href:
                    chapter, _path = findtitle(path.normpath(path.join(dir,href.split('#')[0])), book, "source_path")
                    title = " ".join(href.split("#")[1].split("-")).title()
                    logger.debug(f'Ref has # using title: {title}')
                else:
                    chapter, _path = findtitle(path.normpath(path.join(dir,href.split('#')[0])), book, "source_path")
                    title = chapter["name"]
                    logger.debug(f'Recursive title search result: {chapter["name"]}')
            except Exception as e:
                logger.debug(e)
                logger.error(f'Error getting chapter title: {path.normpath(path.join(dir,href))}')
                sys.exit(1)


    if href.endswith("/README.md"):
        href = href.replace("/README.md", "/index.html")

    template = f"""<a class="content_ref" href="{href}"><span class="content_ref_label">{title}</span></a>"""

    # translate_table = str.maketrans({"\"":"\\\"","\n":"\\n"})
    # translated_text = template.translate(translate_table)
    result = template

    return result


def files(matchobj):
    logger.debug(f'Files match: {matchobj.groups(0)[0].strip()}')
    href =  matchobj.groups(0)[0].strip()
    title = ""

    try:
        for root, dirs, files in os.walk(os.getcwd()+'/src/files'):
            logger.debug(root)
            logger.debug(files)
            if href in files:
                title = href
                logger.debug(f'File search result: {os.path.join(root, href)}')
        
    except Exception as e:
        logger.debug(e)
        logger.error(f'Error searching file: {href}')
        sys.exit(1)

        if title=="":
            logger.error(f'Error searching file: {href}')
            sys.exit(1)

    template = f"""<a class="content_ref" href="/files/{href}"><span class="content_ref_label">{title}</span></a>"""

    result = template

    return result


def add_read_time(content):
    regex = r'(<\/style>\n# .*(?=\n))'
    new_content = re.sub(regex, lambda x: x.group(0) + "\n\nReading time: {{ #reading_time }}", content)
    return new_content


def iterate_chapters(sections):
    if isinstance(sections, dict) and "PartTitle" in sections: # Not a chapter section
        return
    elif isinstance(sections, dict) and "Chapter" in sections: # Is a chapter return it and look into sub items
        # logger.debug(f"Chapter {sections['Chapter']}")
        yield sections['Chapter']
        yield from iterate_chapters(sections['Chapter']["sub_items"])
    elif isinstance(sections, list):                            # Iterate through list when in sections and in sub_items
        for k, v in enumerate(sections):
            yield from iterate_chapters(v)


if __name__ == '__main__':
    global context, book, current_chapter
    if len(sys.argv) > 1: # we check if we received any argument
        if sys.argv[1] == "supports": 
            # then we are good to return an exit status code of 0, since the other argument will just be the renderer's name
            sys.exit(0)
    logger.debug('Started hacktricks preprocessor')
    # load both the context and the book representations from stdin
    context, book = json.load(sys.stdin)

    logger.debug(f"Context: {context}")

    for chapter in iterate_chapters(book['sections']):
        logger.debug(f"Chapter: {chapter['path']}")
        current_chapter = chapter
        # regex = r'{{[\s]*#ref[\s]*}}(?:\n)?([^\\\n]*)(?:\n)?{{[\s]*#endref[\s]*}}'
        regex = r'{{[\s]*#ref[\s]*}}(?:\n)?([^\\\n#]*(?:#(.*))?)(?:\n)?{{[\s]*#endref[\s]*}}'
        new_content = re.sub(regex, ref, chapter['content'])
        regex = r'{{[\s]*#file[\s]*}}(?:\n)?([^\\\n]*)(?:\n)?{{[\s]*#endfile[\s]*}}'
        new_content = re.sub(regex, files, new_content)
        new_content = add_read_time(new_content)
        chapter['content'] = new_content

    content = json.dumps(book)
    logger.debug(content)
    

    print(content)