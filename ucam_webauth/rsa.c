#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <Python.h>
#include <structmember.h>

#if PY_MAJOR_VERSION < 3
#include <bytesobject.h>
#endif

typedef struct
{
    PyObject_HEAD
    RSA *rsa;
}
RSAObject;

static PyObject *verify(RSAObject *self, PyObject *args)
{
    Py_buffer digest, signature;
    int result = 0;
    PyObject *result_obj = NULL;

#if PY_MAJOR_VERSION >= 3
    if (!PyArg_ParseTuple(args, "y*y*:verify", &digest, &signature))
        return NULL;
#else
    if (!PyArg_ParseTuple(args, "s*s*:verify", &digest, &signature))
        return NULL;
#endif

    if (digest.len != SHA_DIGEST_LENGTH)
    {
        PyErr_Format(PyExc_ValueError, "digest should be %i bytes",
                     SHA_DIGEST_LENGTH);
        goto cleanup;
    }

    result = RSA_verify(NID_sha1, digest.buf, digest.len,
                        signature.buf, signature.len, self->rsa);

    result_obj = PyBool_FromLong(result);

cleanup:
    PyBuffer_Release(&digest);
    PyBuffer_Release(&signature);

    return result_obj;
}

static void RSA_dealloc(RSAObject *self)
{
    if (self->rsa)
        RSA_free(self->rsa);
    self->rsa = NULL;
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyMethodDef RSA_methods[] = {
    {"verify", (PyCFunction) verify, METH_VARARGS,
     "verify(sha1_digest, signature)\n\n"
     "Verify a (SHA1) signature, returning ``True`` (valid) or ``False``." },
    {NULL}
};

static PyTypeObject RSAType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "ucam_webauth.rsa.RSA",    /* tp_name */
    sizeof(RSAObject),         /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor) RSA_dealloc,  /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "OpenSSL RSA* wrapper for verifying (SHA1) signatures",
                               /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    RSA_methods,               /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0                          /* tp_new */
};

static PyObject *load_key(PyObject *self, PyObject *args)
{
    Py_buffer data;
    BIO *bio = NULL;
    RSA *rsa = NULL;
    RSAObject *result = NULL;

#if PY_MAJOR_VERSION >= 3
    if (!PyArg_ParseTuple(args, "y*:load_key", &data))
        return NULL;
#else
    if (!PyArg_ParseTuple(args, "s*:load_key", &data))
        return NULL;
#endif

    bio = BIO_new_mem_buf(data.buf, data.len);
    if (bio == NULL)
    {
        PyErr_SetString(PyExc_RuntimeError, "BIO_new_mem_buf");
        goto cleanup;
    }

    if (PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL) == NULL)
    {
        PyErr_SetString(PyExc_ValueError, "invalid PKCS1 key");
        goto cleanup;
    }

    result = PyObject_NEW(RSAObject, &RSAType);
    if (result == NULL)
        goto cleanup;

    result->rsa = rsa;
    rsa = NULL;

cleanup:
    if (rsa)
        RSA_free(rsa);
    if (bio)
        BIO_free(bio);
    PyBuffer_Release(&data);

    return (PyObject *) result;
}

static PyMethodDef rsa_mod_methods[] = {
    {"load_key", load_key, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef rsa_module = {
    PyModuleDef_HEAD_INIT,
    "rsa", NULL, -1, rsa_mod_methods,
    NULL, NULL, NULL, NULL
};

PyObject *PyInit_rsa(void)
{
    PyObject* m;

    if (PyType_Ready(&RSAType) < 0)
        return NULL;

    m = PyModule_Create(&rsa_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&RSAType);
    PyModule_AddObject(m, "RSA", (PyObject *) &RSAType);
    return m;
}

#else

PyMODINIT_FUNC initrsa(void)
{
    PyObject *m;

    if (PyType_Ready(&RSAType) < 0)
        return;

    m = Py_InitModule("rsa", rsa_mod_methods);
    if (m == NULL)
        return;

    Py_INCREF(&RSAType);
    PyModule_AddObject(m, "RSA", (PyObject *) &RSAType);
}
#endif
