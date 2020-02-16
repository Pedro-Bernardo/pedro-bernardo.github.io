---
title: Software Security - Taint Analysis
categories: [Course Work]
tags: [taint analysis]
date: 2019-11-29
---

> **Tools:** Python
> [source code](https://github.com/Pedro-Bernardo/Software-Security-19-20-Taint-Analysis)

This tool analyses python code slices and reports on illegal information flows by performing **Taint Analysis**, a form of **Static Analysis**.
It was developed as a Software Security course project by me and [Tchiclas](https://github.com/Tchiclas)

The following code slice contains lines of code which may impact a data flow between a certain entry point and a sensitive sink. The variable request (which for intuition can be seen as the request parameter of a Django view), is uninstantiated, and can be understood as an entry point. It uses the MySQLCursor.execute() method, which executes the given database operation query.
```python
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
```

The tool essentially searches for certain vulnerable patterns in the slices. All patterns have 4 elements:

name of vulnerability (e.g., SQL injection)
a set of entry points (e.g., request parameter),
a set of sanitization functions (e.g., escape_string),
and a set of sensitive sinks (e.g., execute).

The program signals potential vulnerabilities and sanitization efforts: If it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it signals a potential vulnerability; if the data flow passes through a sanitization function, it signals it as only potentially vulnerable (since the sanitzation might be innefective).


# Running the tool

```
$> python3 parse.py -h                                                                                                                         
usage: python parse slice.json [--config config.json]

to be continued

positional arguments:
  filename

optional arguments:
  -h, --help       show this help message and exit
  --config CONFIG

```
The **slice.json** file should corresponds to the AST (Abstract Syntax Tree) of the slice to be analysed.
**Slice:**
```python
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
``` 

**AST:**
```json
{
  "ast_type": "Module",
  "body": [
    {
      "ast_type": "Assign",
      "col_offset": 0,
      "lineno": 1,
      "targets": [
        {
          "ast_type": "Name",
          "col_offset": 0,
          "ctx": {
            "ast_type": "Store"
          },
          "id": "uname",
          "lineno": 1
        }
      ],
      "value": {
        "args": [
          {
            "ast_type": "Name",
            "col_offset": 23,
            "ctx": {
              "ast_type": "Load"
            },
            "id": "request",
            "lineno": 1
          }
        ],
        "ast_type": "Call",
        "col_offset": 8,
        "func": {
          "ast_type": "Name",
          "col_offset": 8,
          "ctx": {
            "ast_type": "Load"
          },
          "id": "retrieve_uname",
          "lineno": 1
        },
        "keywords": [],
        "lineno": 1
      }
    },
    {
      "ast_type": "Assign",
      "col_offset": 0,
      "lineno": 2,
      "targets": [
        {
          "ast_type": "Name",
          "col_offset": 0,
          "ctx": {
            "ast_type": "Store"
          },
          "id": "q",
          "lineno": 2
        }
      ],
      "value": {
        "args": [
          {
            "ast_type": "BinOp",
            "col_offset": 19,
            "left": {
              "ast_type": "Str",
              "col_offset": 19,
              "lineno": 2,
              "s": "SELECT pass FROM users WHERE user='%s'"
            },
            "lineno": 2,
            "op": {
              "ast_type": "Mod"
            },
            "right": {
              "ast_type": "Name",
              "col_offset": 62,
              "ctx": {
                "ast_type": "Load"
              },
              "id": "uname",
              "lineno": 2
            }
          }
        ],
        "ast_type": "Call",
        "col_offset": 4,
        "func": {
          "ast_type": "Attribute",
          "attr": "execute",
          "col_offset": 4,
          "ctx": {
            "ast_type": "Load"
          },
          "lineno": 2,
          "value": {
            "ast_type": "Name",
            "col_offset": 4,
            "ctx": {
              "ast_type": "Load"
            },
            "id": "cursor",
            "lineno": 2
          }
        },
        "keywords": [],
        "lineno": 2
      }
    }
  ]
}
``` 

The config file provides the vulnerability patterns:
```json
SQL injection
get,get_object_or_404, QueryDict, ContactMailForm, ChatMessageForm
mogrify, escape_string
execute

SQL injection
QueryDict, ContactMailForm, ChatMessageForm, copy, get_query_string, get_user_or_404, User
mogrify, escape_string
raw,RawSQL

XSS
get, get_object_or_404, QueryDict, ContactMailForm, ChatMessageForm
clean,escape,flatatt,render_template,render,render_to_response
send_mail_jinja,mark_safe,Response,Markup,send_mail_jinja,Raw,HTMLString
``` 

# Output
The tool provides a log of the previously mentioned events, and the backtrace of the involved variable's state throughout the AST.



