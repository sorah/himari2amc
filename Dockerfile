FROM public.ecr.aws/lambda/ruby:3.4

RUN --mount=type=cache,target=/var/cache/dnf dnf update -y && dnf install -y gcc gcc-c++ make

COPY src/Gemfile* /var/task/

ENV BUNDLE_JOBS=30
RUN bundle config set path '/opt/vendor/bundle' \
 && bundle config set deployment 'true' \
 && bundle config set without 'development' \
 && mkdir -p /opt/ruby/gems /opt/ruby/lib /opt/vendor/bundle \
 && ln -s /opt/vendor/bundle/ruby/3.4.0 /opt/ruby/gems/3.4.0 \
 && bundle install

RUN cd /opt && zip -r /var/task/layer.zip ruby
RUN unzip -l /var/task/layer.zip

ENTRYPOINT []
CMD ["/bin/bash"]
