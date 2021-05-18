FROM nikoskoutr/open-tee
COPY ./open-tee/CAs /tmp/CAs
COPY ./open-tee/TAs /tmp/TAs

RUN cp -r /tmp/CAs/* /Open-TEE/CAs
RUN cp -r /tmp/TAs/* /Open-TEE/TAs
